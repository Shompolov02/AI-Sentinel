"""Coordinated rebuilding of owned Fluent Bit chunks from the durable outbox."""

from __future__ import annotations

import fcntl
import os
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .storage import share_storage
from .telemetry import Journal

_owners: set[Path] = set()
_owner_guard = threading.RLock()
_buffer_gate = threading.RLock()


@contextmanager
def buffer_gate(directory: Path) -> Iterator[None]:
    """Serialize delivery/reset without holding the SQLite process-wide gate.

    The network call can take five seconds. Health, admission and disk checks
    must still read their database while that delivery is waiting on TLS.
    """
    with _buffer_gate:
        with (directory / "buffer.retention.lock").open("a+b") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)


@contextmanager
def buffer_owner(directory: Path, *, wait: bool = False) -> Iterator[bool]:
    key = directory.resolve()
    with _owner_guard:
        local_owner = key in _owners
        if not local_owner:
            _owners.add(key)
    if local_owner:
        yield False
        return
    try:
        with (directory / "fluent-owner.lock").open("a+b") as stream:
            if os.environ.get("COWRIE_STORAGE_GROUP"):
                share_storage(
                    Path(stream.name), int(os.environ["COWRIE_STORAGE_GROUP"])
                )
            acquired = False
            try:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
                    acquired = True
                except BlockingIOError:
                    pass
                yield acquired
            finally:
                if acquired:
                    fcntl.flock(stream, fcntl.LOCK_UN)
    finally:
        with _owner_guard:
            _owners.discard(key)


def requested_cutoff(journal: Journal) -> float | None:
    with journal.connection() as db:
        row = db.execute("SELECT cutoff FROM buffer_retention WHERE id=1").fetchone()
        return float(row[0]) if row else None


def erase_chunks(journal: Journal, cutoff: float) -> None:
    """Caller owns the child lease and has stopped/waited for Fluent Bit."""
    root = journal.database.parent / "chunks"
    if root.is_symlink():
        raise OSError("Invalid chunk directory")
    if root.exists():
        # Erase bytes before unlink so an open descriptor cannot retain text.
        for directory, dirs, files in os.walk(root, followlinks=False):
            for name in dirs:
                if (Path(directory) / name).is_symlink():
                    raise OSError("Invalid chunk subtree")
            for name in files:
                path = Path(directory) / name
                fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
                try:
                    os.ftruncate(fd, 0)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                path.unlink()
    with journal.connection() as db:
        db.execute("DELETE FROM buffer_retention WHERE cutoff <= ?", (cutoff,))


def maintain_collector(journal: Journal, now: float) -> None:
    journal.expire_text(now)
    journal.expire_metadata(now)
    if requested_cutoff(journal) is None:
        return
    with buffer_owner(journal.database.parent) as owns_child:
        if owns_child:
            cutoff = requested_cutoff(journal)
            if cutoff is not None:
                erase_chunks(journal, cutoff)
            return
    # The running supervisor owns reset. Never remove live child files here.
    limit = time.monotonic() + 15
    while requested_cutoff(journal) is not None:
        if time.monotonic() >= limit:
            raise OSError("Collector buffer cleanup remains pending")
        time.sleep(0.05)
