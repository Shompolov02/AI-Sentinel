"""Critical episodes; pending storage failures survive in memory until writable."""

import sqlite3
from threading import RLock
from typing import Any
from uuid import uuid4

from .storage import METADATA_TTL
from .store import Store


class CriticalAlerts:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.lock = RLock()
        with store.connection() as db:
            self.current = {
                row["code"] + ":" + (row["task_id"] or ""): dict(row)
                for row in db.execute(
                    "SELECT * FROM core_alerts WHERE resolved_at IS NULL ORDER BY at"
                )
            }
        self.pending: dict[str, dict[str, Any]] = {}

    def prune(self, now: float, live_tasks: set[str] | None = None) -> None:
        def keep(episode: dict[str, Any]) -> bool:
            return episode["at"] + METADATA_TTL > now and (
                live_tasks is None
                or episode["task_id"] is None
                or episode["task_id"] in live_tasks
            )

        self.current = {
            key: value for key, value in self.current.items() if keep(value)
        }
        self.pending = {
            key: value for key, value in self.pending.items() if keep(value)
        }

    def raise_alert(self, code: str, now: float, task_id: str | None = None) -> bool:
        with self.lock:
            self.prune(now)
            key = code + ":" + (task_id or "")
            if key in self.current:
                return False
            episode: dict[str, Any] = {
                "id": str(uuid4()),
                "at": now,
                "code": code,
                "task_id": task_id,
                "resolved_at": None,
            }
            self.current[key] = episode
            self.pending[episode["id"]] = episode
            return True

    def resolve(self, code: str, now: float, task_id: str | None = None) -> None:
        with self.lock:
            self.prune(now)
            episode = self.current.pop(code + ":" + (task_id or ""), None)
            if episode is not None:
                episode["resolved_at"] = now
                self.pending[episode["id"]] = episode

    def active(self) -> list[dict[str, Any]]:
        with self.lock:
            with self.store.connection() as db:
                live = {
                    row[0]
                    for row in db.execute(
                        "SELECT task_id FROM task_retention WHERE expires > ?",
                        (self.store.clock(),),
                    )
                }
            self.prune(self.store.clock(), live)
            return [dict(episode) for episode in self.current.values()]

    def flush(self) -> None:
        with self.lock:
            self.prune(self.store.clock())
            if not self.pending:
                return
            try:
                with self.store.connection() as db:
                    db.execute("BEGIN IMMEDIATE")
                    live = {
                        row[0]
                        for row in db.execute(
                            "SELECT task_id FROM task_retention WHERE expires > ?",
                            (self.store.clock(),),
                        )
                    }
                    self.prune(self.store.clock(), live)
                    db.executemany(
                        "INSERT INTO core_alerts VALUES "
                        "(:id,:at,:code,:task_id,:resolved_at) "
                        "ON CONFLICT(id) DO UPDATE "
                        "SET resolved_at=excluded.resolved_at",
                        list(self.pending.values()),
                    )
            except (sqlite3.Error, OSError):
                # A failed recovery write is not evidence of recovery. Keep the
                # same episode active rather than creating one per page refresh.
                for episode in self.pending.values():
                    key = episode["code"] + ":" + (episode["task_id"] or "")
                    if episode["resolved_at"] is not None and key not in self.current:
                        episode["resolved_at"] = None
                        self.current[key] = episode
                raise
            self.pending.clear()
