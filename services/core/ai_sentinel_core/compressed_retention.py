"""Recoverable replacement of sealed gzip copies; never spool plaintext to disk."""

from __future__ import annotations

import gzip
import hashlib
import os
import sqlite3
import stat
import struct
import zlib
from collections.abc import Callable
from contextlib import nullcontext
from pathlib import Path
from typing import Any, BinaryIO
from uuid import uuid4

from .storage import TEXT_TTL
from .telemetry import MAX_LINE, Journal


def digest_stream(stream: BinaryIO) -> str:
    stream.seek(0)
    digest = hashlib.sha256()
    while block := stream.read(MAX_LINE):
        digest.update(block)
    stream.seek(0)
    return digest.hexdigest()


def open_regular(path: Path) -> BinaryIO:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(descriptor, "rb")
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        stream.close()
        raise OSError("Archive is not a regular file")
    return stream


def recover_directory(db: sqlite3.Connection, directory: Path) -> None:
    for row in db.execute("SELECT path FROM compressed_jobs").fetchall():
        path = Path(row[0])
        if path.parent == directory.absolute():
            recover(db, path)


def zero_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("Archive erasure target is not regular")
        size = info.st_size
        position = 0
        while position < size:
            count = os.pwrite(
                descriptor, b"\0" * min(MAX_LINE, size - position), position
            )
            if count <= 0:
                raise OSError("Incomplete archive erasure")
            position += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def sync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def register(db: sqlite3.Connection, path: Path, job: Any) -> None:
    info = path.stat(follow_symlinks=False)
    db.execute(
        "INSERT OR REPLACE INTO compressed_files VALUES (?,?,?,?,?,?,?)",
        (
            str(path),
            job["kind"],
            job["generation"],
            info.st_dev,
            info.st_ino,
            job["output_digest"] or job["digest"],
            job["received"],
        ),
    )


def recover(db: sqlite3.Connection, path: Path) -> None:
    job = db.execute(
        "SELECT * FROM compressed_jobs WHERE path=?", (str(path),)
    ).fetchone()
    if job is None:
        return
    name = job["temporary"]
    if Path(name).name != name or not name.startswith(".retention-"):
        raise OSError("Invalid archive recovery path")
    temporary = path.parent / name
    if job["output_digest"] is None:
        if temporary.exists():
            zero_file(temporary)
            temporary.unlink()
            sync_directory(path.parent)
        db.execute("DELETE FROM compressed_jobs WHERE path=?", (str(path),))
        db.commit()
        return
    if not path.exists():
        candidates = []
        for candidate in path.parent.glob("*.gz"):
            if candidate.name.startswith(".retention-") or candidate.is_symlink():
                continue
            info = candidate.stat(follow_symlinks=False)
            if (info.st_dev, info.st_ino) == (job["device"], job["inode"]):
                candidates.append(candidate)
            else:
                with open_regular(candidate) as stream:
                    if digest_stream(stream) == job["output_digest"]:
                        candidates.append(candidate)
        if len(candidates) != 1:
            raise OSError("Renamed archive recovery is not uniquely available")
        db.execute(
            "UPDATE compressed_jobs SET path=? WHERE path=?",
            (str(candidates[0]), str(path)),
        )
        db.commit()
        path = candidates[0]
    # The ready output is durable before any byte of the old inode is erased.
    if temporary.exists():
        with open_regular(temporary) as stream:
            if digest_stream(stream) != job["output_digest"]:
                raise OSError("Archive recovery output changed")
        info = path.stat(follow_symlinks=False)
        if (info.st_dev, info.st_ino) != (job["device"], job["inode"]):
            raise OSError("Archive source replaced during recovery")
        zero_file(path)
        os.replace(temporary, path)
        sync_directory(path.parent)
    else:
        # Replacement completed but the database commit was interrupted.
        with open_regular(path) as stream:
            if digest_stream(stream) != job["output_digest"]:
                raise OSError("Archive replacement cannot be confirmed")
    register(db, path, job)
    db.execute("DELETE FROM compressed_jobs WHERE path=?", (str(path),))
    db.commit()


def verified_receipts(
    db: sqlite3.Connection,
    source: BinaryIO,
    generation: str | None,
) -> dict[int, float | None]:
    receipts: dict[int, float | None] = {}
    source.seek(0)
    with gzip.GzipFile(fileobj=source, mode="rb") as logical:
        while True:
            position = logical.tell()
            block = logical.readline(MAX_LINE + 1)
            if not block:
                break
            digest = hashlib.sha256()
            length = 0
            while True:
                digest.update(block)
                length += len(block)
                if block.endswith(b"\n"):
                    break
                block = logical.readline(MAX_LINE + 1)
                if not block:
                    break  # A sealed archive can end with an unknown partial line.
            row = db.execute(
                "SELECT r.received,r.length,d.digest FROM source_ranges r "
                "JOIN source_digests d USING(reference) "
                "WHERE r.generation=? AND r.position=?",
                (generation, position),
            ).fetchone()
            if row and row[1] == length and row[2] == digest.hexdigest():
                receipts[position] = row[0]
    source.seek(0)
    return receipts


def clean_compressed(
    journal: Journal,
    path: Path,
    now: float,
    *,
    kind: str = "raw",
    receipt: float | None = None,
    line_receipt: Callable[[bytes], float | None] | None = None,
    connection: sqlite3.Connection | None = None,
) -> None:
    path = path.absolute()
    with journal.connection() if connection is None else nullcontext(connection) as db:
        recover(db, path)
        with open_regular(path) as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise OSError("Archive is not a regular file")
            digest = digest_stream(source)
            previous = db.execute(
                "SELECT * FROM compressed_files "
                "WHERE device=? AND inode=? AND digest=?",
                (info.st_dev, info.st_ino, digest),
            ).fetchone()
            generation = previous["generation"] if previous else None
            if previous:
                receipt = previous["received"]
            try:
                with gzip.GzipFile(fileobj=source, mode="rb") as logical:
                    first = logical.readline(MAX_LINE + 1)
                if kind == "raw" and generation is None:
                    candidates = db.execute(
                        "SELECT DISTINCT generation FROM source_prefixes "
                        "WHERE digest=?",
                        (hashlib.sha256(first).hexdigest(),),
                    ).fetchall()
                    if len(candidates) > 1:
                        raise OSError("Ambiguous archive provenance")
                    generation = candidates[0][0] if candidates else None
                receipts = (
                    verified_receipts(db, source, generation) if kind == "raw" else {}
                )
                name = ".retention-" + uuid4().hex + ".gz"
                temporary = path.parent / name
                db.execute(
                    "INSERT INTO compressed_jobs VALUES (?,?,?,?,?,?,?,?,NULL)",
                    (
                        str(path),
                        name,
                        kind,
                        generation,
                        receipt,
                        info.st_dev,
                        info.st_ino,
                        digest,
                    ),
                )
                db.commit()
                source.seek(0)
                # Canonical gzip headers contain no filename/comment text.
                changed = previous is None
                with temporary.open("xb") as output:
                    if journal.shared_group is not None:
                        os.fchmod(output.fileno(), 0o640)
                    with (
                        gzip.GzipFile(fileobj=source, mode="rb") as logical,
                        gzip.GzipFile(
                            fileobj=output, mode="wb", filename="", mtime=0
                        ) as target,
                    ):
                        while True:
                            position = logical.tell()
                            if kind == "tty":
                                header = logical.read(24)
                                if not header:
                                    break
                                if len(header) != 24:
                                    raise OSError("Incomplete archived TTY header")
                                op, _, length, _, _, _ = struct.unpack(
                                    "<iLiiLL", header
                                )
                                if op not in (1, 2, 3, 4) or length < 0:
                                    raise OSError("Invalid archived TTY frame")
                                target.write(header)
                                due = receipt is None or receipt + TEXT_TTL <= now
                                while length:
                                    block = logical.read(min(length, MAX_LINE))
                                    if not block:
                                        raise OSError("Incomplete archived TTY frame")
                                    replacement = (
                                        bytes(10 if b == 10 else 32 for b in block)
                                        if due
                                        else block
                                    )
                                    changed = changed or replacement != block
                                    target.write(replacement)
                                    length -= len(block)
                                continue
                            block = logical.readline(MAX_LINE + 1)
                            if not block:
                                break
                            received = receipt
                            if kind == "raw":
                                received = receipts.get(position)
                            elif line_receipt is not None:
                                received = line_receipt(block)
                            due = received is None or received + TEXT_TTL <= now
                            while True:
                                replacement = (
                                    bytes(10 if b == 10 else 32 for b in block)
                                    if due
                                    else block
                                )
                                changed = changed or replacement != block
                                target.write(replacement)
                                if block.endswith(b"\n"):
                                    break
                                block = logical.readline(MAX_LINE + 1)
                                if not block:
                                    break  # Erase the tail without changing length.
                    output.flush()
                    os.fsync(output.fileno())
                sync_directory(path.parent)
            except (EOFError, zlib.error) as error:
                raise OSError("Invalid compressed source") from error
            # No external archiver may mutate a sealed input while it is serviced.
            current = path.stat(follow_symlinks=False)
            if (
                current.st_dev,
                current.st_ino,
                current.st_size,
                current.st_mtime_ns,
            ) != (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
            ) or digest_stream(source) != digest:
                raise OSError("Archive changed during cleanup")
            if changed:
                with open_regular(temporary) as stream:
                    output_digest = digest_stream(stream)
                db.execute(
                    "UPDATE compressed_jobs SET output_digest=? WHERE path=?",
                    (output_digest, str(path)),
                )
                db.commit()
                recover(db, path)
            else:
                job = db.execute(
                    "SELECT * FROM compressed_jobs WHERE path=?", (str(path),)
                ).fetchone()
                register(db, path, job)
                db.commit()
                recover(db, path)
