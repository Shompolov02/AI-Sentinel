"""Range-based removal of auxiliary Cowrie copies without truncating writers."""

from __future__ import annotations

import os
import struct
from pathlib import Path

from .compressed_retention import clean_compressed, recover_directory
from .storage import TEXT_TTL
from .telemetry import MAX_LINE, Journal

HEADER = struct.Struct("<iLiiLL")


def clean_auxiliary(
    journal: Journal,
    logs: Path,
    downloads: Path | None,
    now: float,
    *,
    tty_directory: Path | None = None,
) -> None:
    with journal.connection() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS auxiliary_ranges (
                identity TEXT, position INTEGER, length INTEGER, received REAL,
                state TEXT NOT NULL DEFAULT 'live', PRIMARY KEY(identity, position)
            );
            CREATE TABLE IF NOT EXISTS auxiliary_meta (id INTEGER PRIMARY KEY);
        """)
        db.execute(
            "CREATE TABLE IF NOT EXISTS auxiliary_bindings ("
            "identity TEXT PRIMARY KEY, received REAL)"
        )
        sessions = {
            row[0]: row[1]
            for row in db.execute("SELECT session, received FROM session_receipts")
        }

        def earliest(values: list[float | None]) -> float | None:
            known = [value for value in values if value is not None]
            return min(known) if known and len(known) == len(values) else None

        anonymous_receipt = earliest(list(sessions.values()))
        paths = [(p, "line") for p in logs.glob("cowrie.log*")]
        tty = tty_directory if tty_directory is not None else logs / "tty"
        if tty.exists():
            paths += [(p, "tty") for p in tty.iterdir()]
        if downloads is not None and downloads.exists():
            paths += [(p, "artifact") for p in downloads.iterdir()]
        for directory in {logs, tty}:
            recover_directory(db, directory)
        for path, kind in paths:
            if path.is_symlink() or not path.is_file():
                raise OSError("Auxiliary source is not a regular file")
            if path.suffix == ".gz" and kind != "artifact":
                base = path.name[:-3]
                names = [
                    session
                    for session in sessions
                    if f"-{session}-" in base or base == f"{session}.log"
                ]
                names += [
                    row[0]
                    for row in db.execute(
                        "SELECT session FROM session_artifacts WHERE name=?", (base,)
                    )
                ]
                receipt = (
                    earliest([sessions[n] for n in names if n in sessions])
                    if names
                    else anonymous_receipt
                )

                def line_receipt(data: bytes) -> float | None:
                    prefix = (
                        data.split(b"[", 1)[1].split(b"]", 1)[0]
                        if b"[" in data
                        else b""
                    )
                    found = [
                        sessions[field]
                        for field in prefix.decode("utf-8", errors="replace").split(",")
                        if field in sessions
                    ]
                    return earliest(found) if found else anonymous_receipt

                clean_compressed(
                    journal,
                    path,
                    now,
                    kind=kind,
                    receipt=receipt,
                    line_receipt=line_receipt if kind == "line" else None,
                    connection=db,
                )
                continue
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
            try:
                stat = os.fstat(fd)
                identity = f"{stat.st_dev}:{stat.st_ino}"
                bound = db.execute(
                    "SELECT received FROM auxiliary_bindings WHERE identity=?",
                    (identity,),
                ).fetchone()
                if bound is None:
                    names = [
                        session
                        for session in sessions
                        if f"-{session}-" in path.name or path.name == f"{session}.log"
                    ]
                    names += [
                        row[0]
                        for row in db.execute(
                            "SELECT session FROM session_artifacts WHERE name=?",
                            (path.name,),
                        )
                    ]
                    file_receipt = (
                        earliest([sessions[name] for name in names if name in sessions])
                        if names
                        else anonymous_receipt
                    )
                    db.execute(
                        "INSERT INTO auxiliary_bindings VALUES (?,?)",
                        (identity, file_receipt),
                    )
                else:
                    file_receipt = bound[0]
                position = 0
                while position < stat.st_size:
                    if kind == "tty":
                        raw_header = os.pread(fd, HEADER.size, position)
                        if len(raw_header) != HEADER.size:
                            break
                        op, _, length, _direction, _sec, _usec = HEADER.unpack(
                            raw_header
                        )
                        if op not in (1, 2, 3, 4) or length < 0:
                            raise OSError("Invalid TTY frame")
                        if position + HEADER.size + length > stat.st_size:
                            # Slow writes cannot extend an expired session;
                            # preserve its header and append position.
                            if file_receipt is None or file_receipt + TEXT_TTL <= now:
                                db.commit()
                                available = stat.st_size - position - HEADER.size
                                erase_payload(fd, position + HEADER.size, available)
                            break
                        start = position + HEADER.size
                        range_length = length
                        data = b""
                        position = start + length
                    else:
                        start = position
                        limit = min(MAX_LINE, stat.st_size - start)
                        if kind == "artifact":
                            previous = db.execute(
                                "SELECT length FROM auxiliary_ranges "
                                "WHERE identity=? AND position=?",
                                (identity, start),
                            ).fetchone()
                            if previous:
                                if previous[0] > stat.st_size - start:
                                    raise OSError("Captured artifact was truncated")
                                limit = previous[0]
                        data = os.pread(fd, limit, start)
                        position += len(data)
                        if kind == "line":
                            first_block = data
                            block = data
                            while b"\n" not in block and position < stat.st_size:
                                block = os.pread(
                                    fd, min(MAX_LINE, stat.st_size - position), position
                                )
                                if not block:
                                    break
                                position += len(block)
                            if b"\n" not in block:
                                break
                            position -= len(block) - block.index(b"\n") - 1
                            data = first_block
                        range_length = position - start
                    if not range_length:
                        continue
                    prior = db.execute(
                        "SELECT received, state, length FROM auxiliary_ranges "
                        "WHERE identity = ? AND position = ?",
                        (identity, start),
                    ).fetchone()
                    if prior and prior[2] != range_length:
                        raise OSError("Auxiliary source changed its recorded range")
                    if prior and prior[1] == "erased":
                        continue
                    received = file_receipt
                    if kind == "line":
                        prefix = (
                            data.split(b"[", 1)[1].split(b"]", 1)[0]
                            if b"[" in data
                            else b""
                        )
                        fields = prefix.decode("utf-8", errors="replace").split(",")
                        identified = [
                            sessions[field] for field in fields if field in sessions
                        ]
                        if identified:
                            received = earliest(identified)
                    if prior and prior[0] is None:
                        received = None
                    elif prior and received is not None:
                        received = min(received, prior[0])
                    db.execute(
                        "INSERT INTO auxiliary_ranges"
                        "(identity,position,length,received) "
                        "VALUES (?,?,?,?) ON CONFLICT(identity,position) DO UPDATE "
                        "SET received=excluded.received",
                        (identity, start, range_length, received),
                    )
                    if received is None or received + TEXT_TTL <= now:
                        # Commit intent before bytes change; a retry overwrites the
                        # same finite range. No auxiliary text is stored in SQLite.
                        db.execute(
                            "UPDATE auxiliary_ranges SET state='prepared' "
                            "WHERE identity=? AND position=?",
                            (identity, start),
                        )
                        db.commit()
                        erase_payload(fd, start, range_length)
                        db.execute(
                            "UPDATE auxiliary_ranges SET state='erased' "
                            "WHERE identity=? AND position=?",
                            (identity, start),
                        )
                db.commit()
            finally:
                os.close(fd)
        db.execute("INSERT OR IGNORE INTO auxiliary_meta VALUES (1)")


def erase_payload(fd: int, position: int, length: int) -> None:
    end = position + length
    while position < end:
        size = min(MAX_LINE, end - position)
        data = os.pread(fd, size, position)
        if len(data) != size:
            raise OSError("Auxiliary source changed during erasure")
        # Preserve line framing; TTY headers are outside this payload range.
        replacement = bytes(10 if byte == 10 else 32 for byte in data)
        written = 0
        while written < size:
            count = os.pwrite(fd, replacement[written:], position + written)
            if count <= 0:
                raise OSError("Incomplete auxiliary cleanup")
            written += count
        position += size
    os.fsync(fd)
