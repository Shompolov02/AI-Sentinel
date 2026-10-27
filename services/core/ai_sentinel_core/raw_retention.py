"""Erase expired ranges in place, retaining fresh offsets and append writers."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .compressed_retention import clean_compressed, recover_directory
from .storage import TEXT_TTL
from .telemetry import MAX_LINE, Journal


def erase_range(fd: int, position: int, length: int) -> None:
    # Never truncate, replace the inode, or touch the writer's append position.
    end = position + length
    while position < end:
        size = min(65536, end - position)
        chunk = b" " * size
        if position + size == end:
            chunk = chunk[:-1] + b"\n"
        written = os.pwrite(fd, chunk, position)
        if written <= 0:
            raise OSError("Incomplete source cleanup")
        position += written
    os.fsync(fd)


def clean_raw(journal: Journal, directory: Path, now: float) -> None:
    with journal.connection() as db:
        recover_directory(db, directory)
    journal.scan(directory)
    for archive in sorted(directory.glob("cowrie.json*.gz")):
        clean_compressed(journal, archive, now)
    # Prepared operations survive interruption. The pre-erase identity must be
    # saved too: first-line erasure changes that fingerprint before commit.
    with journal.connection() as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS erasure_files ("
            "generation TEXT PRIMARY KEY, device INTEGER, inode INTEGER)"
        )
        rows = db.execute(
            "SELECT DISTINCT f.generation, f.identity FROM files f "
            "JOIN source_ranges r "
            "USING (generation) WHERE (r.received IS NULL OR r.received + ? <= ?) "
            "AND r.state != 'erased'",
            (TEXT_TTL, now),
        ).fetchall()
        for row in rows:
            device, inode, _ = row["identity"].split(":", 2)
            db.execute(
                "INSERT OR IGNORE INTO erasure_files VALUES (?,?,?)",
                (row["generation"], int(device), int(inode)),
            )
        db.execute(
            "UPDATE source_ranges SET state = 'prepared' "
            "WHERE (received IS NULL OR received + ? <= ?) AND state = 'live'",
            (TEXT_TTL, now),
        )
    with journal.connection() as db:
        for file in db.execute("SELECT * FROM erasure_files").fetchall():
            candidates = []
            for path in directory.glob("cowrie.json*"):
                if path.is_file() and not path.is_symlink() and path.suffix != ".gz":
                    stat = path.stat()
                    if (stat.st_dev, stat.st_ino) == (file["device"], file["inode"]):
                        candidates.append(path)
            if (
                not candidates
                and db.execute(
                    "SELECT 1 FROM compressed_files WHERE generation=?",
                    (file["generation"],),
                ).fetchone()
            ):
                db.execute(
                    "UPDATE source_ranges SET state='erased' "
                    "WHERE generation=? AND state='prepared'",
                    (file["generation"],),
                )
                continue
            if len(candidates) != 1:
                raise OSError("Source generation not uniquely available")
            path = candidates[0]
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
            try:
                actual = os.fstat(fd)
                if (actual.st_dev, actual.st_ino) != (file["device"], file["inode"]):
                    raise OSError("Source identity changed during erasure")
                size = actual.st_size
                for record in db.execute(
                    "SELECT * FROM source_ranges WHERE generation = ? "
                    "AND state = 'prepared'",
                    (file["generation"],),
                ).fetchall():
                    if record["position"] + record["length"] > size:
                        raise OSError("Source changed during erasure")
                    erase_range(fd, record["position"], record["length"])
                prefix = os.pread(fd, MAX_LINE + 1, 0)
                first = prefix[: prefix.index(b"\n") + 1] if b"\n" in prefix else prefix
                identity = (
                    f"{file['device']}:{file['inode']}:"
                    + hashlib.sha256(first).hexdigest()
                )
                db.execute(
                    "UPDATE files SET identity = ?, path = ? WHERE generation = ?",
                    (identity, path.name, file["generation"]),
                )
                db.execute(
                    "UPDATE source_ranges SET state = 'erased' "
                    "WHERE generation = ? AND state = 'prepared'",
                    (file["generation"],),
                )
            finally:
                os.close(fd)
        db.execute("DELETE FROM erasure_files")
        db.execute(
            "DELETE FROM quarantine WHERE reference IN "
            "(SELECT reference FROM source_ranges WHERE state = 'erased')"
        )
