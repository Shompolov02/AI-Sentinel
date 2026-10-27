"""SQLite connections that scrub removed text and truncate committed journals."""

from __future__ import annotations

import fcntl
import os
import sqlite3
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

TEXT_TTL = 14 * 86400
METADATA_TTL = 30 * 86400
_gate = threading.RLock()


def share_storage(path: Path, group: int, *, directory: bool = False) -> None:
    info = path.lstat()
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise OSError("Shared collector storage is not regular")
    permissions = 0o2770 if directory else 0o660
    if info.st_uid == os.geteuid():
        os.chown(path, -1, group, follow_symlinks=False)
        os.chmod(path, permissions, follow_symlinks=False)
    elif info.st_gid != group or info.st_mode & 0o070 != permissions & 0o070:
        raise PermissionError("Collector storage group is not ready")


@contextmanager
def file_gate(
    path: Path, *, readonly: bool = False, group: int | None = None
) -> Iterator[None]:
    """Coordinate filesystem erasure with normalizer and reader snapshots."""
    with _gate:
        with Path(str(path) + ".retention.lock").open(
            "rb" if readonly else "a+b"
        ) as lock:
            if group is not None and not readonly:
                share_storage(Path(str(path) + ".retention.lock"), group)
            fcntl.flock(lock, fcntl.LOCK_SH if readonly else fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)


def text_expired(event: dict[str, Any], now: float) -> bool:
    try:
        received = datetime.fromisoformat(
            event["received_at"].replace("Z", "+00:00")
        ).timestamp()
    except (KeyError, ValueError, TypeError, AttributeError):
        # Legacy text without a receipt must not acquire a new lifetime.
        return True
    return now >= received + TEXT_TTL


def connect(path: Path, timeout: float = 3) -> sqlite3.Connection:
    db = sqlite3.connect(path, timeout=timeout)
    try:
        db.row_factory = sqlite3.Row
        if db.execute("PRAGMA journal_mode").fetchone()[0] != "truncate":
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            if db.execute("PRAGMA journal_mode=TRUNCATE").fetchone()[0] != "truncate":
                raise sqlite3.OperationalError("Retention journal mode unavailable")
        for setting, value in (
            ("secure_delete", 1),
            ("synchronous", 2),
            ("temp_store", 2),
        ):
            db.execute(f"PRAGMA {setting}={value}")
            if db.execute(f"PRAGMA {setting}").fetchone()[0] != value:
                raise sqlite3.OperationalError("Retention storage profile unavailable")
        return db
    except BaseException:
        db.close()
        raise
