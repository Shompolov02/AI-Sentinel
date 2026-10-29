"""Collector admission budgets; delivery and retention keep running when paused."""

from __future__ import annotations

import logging
import os
import shutil
from typing import Any

from .telemetry import Journal

logger = logging.getLogger("ai_sentinel_telemetry")
CHUNK_RESERVE = 2 * 1024**2


class Pressure:
    def __init__(self, journal: Journal) -> None:
        self.journal = journal
        self.chunk_limit = int(os.environ.get("COLLECTOR_CHUNK_BYTES", 64 * 1024**2))
        if self.chunk_limit < 2 * CHUNK_RESERVE:
            raise ValueError("Chunk budget must be at least 4 MiB")

    def core_depth(self, depth: int) -> None:
        self.journal.pressure_value("core_depth", max(0, depth))

    def snapshot(self) -> dict[str, Any]:
        with self.journal.connection() as db:
            root = self.journal.database.parent
            outbox = int(
                db.execute(
                    "SELECT coalesce(sum(length(CAST(payload AS BLOB))),0) "
                    "FROM outbox WHERE payload != '{}'"
                ).fetchone()[0]
            )
            values = dict(db.execute("SELECT name,value FROM collector_pressure"))
            chunks = 0
            for path in (root / "chunks").rglob("*"):
                try:
                    if path.is_file():
                        chunks += path.stat().st_size
                except FileNotFoundError:
                    # Fluent Bit may unlink a successfully flushed chunk while
                    # this read-only snapshot enumerates its directory.
                    continue
            depth = values.get("core_depth", 0)
            # Keep room for SQLite rollback journals and bounded Fluent Bit writes.
            reserve = (
                2 * max(self.journal.database.stat().st_size, 8 * 1024**2)
                + CHUNK_RESERVE
            )
            disk_low = shutil.disk_usage(root).free < reserve
            blocked = bool(values.get("outbox_blocked", 0))
            if blocked and outbox * 100 <= self.journal.outbox_limit * 60:
                db.execute(
                    "INSERT OR REPLACE INTO collector_pressure "
                    "VALUES ('outbox_blocked',0)"
                )
                blocked = False
            before = values.get("mode", 0)
            stop = (
                blocked
                or outbox >= self.journal.outbox_limit
                or chunks + CHUNK_RESERVE > self.chunk_limit
                or depth >= 1000
                or disk_low
            )
            low = (
                outbox * 100 <= self.journal.outbox_limit * 60
                and chunks * 100 <= self.chunk_limit * 60
                and depth <= 600
                and not disk_low
            )
            high = (
                outbox * 100 >= self.journal.outbox_limit * 80
                or chunks * 100 >= self.chunk_limit * 80
                or depth >= 800
            )
            mode = 2 if stop else (0 if low else max(before, 1 if high else 0))
            if mode != before:
                db.execute(
                    "INSERT OR REPLACE INTO collector_pressure VALUES ('mode',?)",
                    (mode,),
                )
                code = (
                    "collector_intake_resumed",
                    "collector_backpressure",
                    "collector_intake_stopped",
                )[mode]
                logger.log(
                    logging.CRITICAL
                    if mode == 2
                    else logging.WARNING
                    if mode == 1
                    else logging.INFO,
                    "%s outbox_bytes=%s chunk_bytes=%s core_depth=%s disk_low=%s",
                    code,
                    outbox,
                    chunks,
                    depth,
                    disk_low,
                )
            return {
                "status": "ok",
                "intake": ("normal", "slowed", "stopped")[mode],
                "outbox_bytes": outbox,
                "chunk_bytes": chunks,
                "core_queue_depth": depth,
                "scan_interval_seconds": 2 if mode == 0 else 10,
                "disk_reserve_bytes": reserve,
                "disk_low": disk_low,
            }
