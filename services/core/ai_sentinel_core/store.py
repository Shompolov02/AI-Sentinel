from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import HTTPException

logger = logging.getLogger("ai_sentinel_core")


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY, event_id TEXT UNIQUE NOT NULL,
                    event TEXT NOT NULL, state TEXT NOT NULL,
                    created REAL NOT NULL, verdict TEXT, evidence TEXT
                );
                CREATE TABLE IF NOT EXISTS login_observations (
                    task_id TEXT PRIMARY KEY, source_ip TEXT NOT NULL,
                    occurred REAL NOT NULL, failure INTEGER NOT NULL,
                    failure_count INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS login_window
                    ON login_observations (source_ip, failure, occurred);
                CREATE TABLE IF NOT EXISTS sessions (
                    digest TEXT PRIMARY KEY, last_active REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY, at REAL NOT NULL,
                    action TEXT NOT NULL, actor TEXT NOT NULL,
                    task_id TEXT, details TEXT NOT NULL
                );
            """)
            # Upgrade the accepted-event history without revisiting old verdicts.
            db.execute("BEGIN IMMEDIATE")
            for row in db.execute(
                "SELECT t.id, t.event FROM tasks t LEFT JOIN login_observations o "
                "ON o.task_id = t.id WHERE o.task_id IS NULL ORDER BY t.rowid"
            ).fetchall():
                self.observe_login(db, row["id"], json.loads(row["event"]))

    @staticmethod
    def observe_login(
        db: sqlite3.Connection, task_id: str, event: dict[str, Any]
    ) -> None:
        occurred = datetime.fromisoformat(
            event["occurred_at"].replace("Z", "+00:00")
        ).timestamp()
        failure = event["login"]["outcome"] == "failure"
        count = db.execute(
            "SELECT count(*) FROM login_observations "
            "WHERE source_ip = ? AND failure = 1 AND occurred BETWEEN ? AND ?",
            (event["source_ip"], occurred - 300, occurred),
        ).fetchone()[0] + int(failure)
        db.execute(
            "INSERT INTO login_observations VALUES (?,?,?,?,?)",
            (task_id, event["source_ip"], occurred, int(failure), count),
        )

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=3)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def login(self, digest: str, now: float) -> None:
        with self.connection() as db:
            db.execute("INSERT INTO sessions VALUES (?, ?)", (digest, now))
            self.audit(db, now, "login_succeeded", "SecOps", None, {})

    def authenticate(self, digest: str, now: float, touch: bool = True) -> bool:
        with self.connection() as db:
            db.execute("DELETE FROM sessions WHERE last_active <= ?", (now - 1800,))
            if not touch:
                return (
                    db.execute(
                        "SELECT 1 FROM sessions WHERE digest = ?", (digest,)
                    ).fetchone()
                    is not None
                )
            return (
                db.execute(
                    "UPDATE sessions SET last_active = ? WHERE digest = ?",
                    (now, digest),
                ).rowcount
                == 1
            )

    @staticmethod
    def audit(
        db: sqlite3.Connection,
        now: float,
        action: str,
        actor: str,
        task_id: str | None,
        details: dict[str, object],
    ) -> None:
        db.execute(
            "INSERT INTO audit (at, action, actor, task_id, details) "
            "VALUES (?,?,?,?,?)",
            (now, action, actor, task_id, json.dumps(details)),
        )

    def accept(self, event: str, event_id: str, now: float) -> dict[str, str]:
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute(
                "SELECT * FROM tasks WHERE event_id = ?", (event_id,)
            ).fetchone()
            if prior:
                if prior["event"] != event:
                    raise HTTPException(409, "Event ID content conflict")
                return {
                    "task_id": prior["id"],
                    "correlation_id": prior["id"],
                    "state": prior["state"],
                }
            count = db.execute(
                "SELECT count(*) FROM tasks WHERE state IN ('queued','processing')"
            ).fetchone()[0]
            if count >= 1000:
                logger.warning("intake_capacity_reached")
                raise HTTPException(503, "Intake capacity reached; retry later")
            task_id = str(uuid4())
            db.execute(
                "INSERT INTO tasks (id,event_id,event,state,created) "
                "VALUES (?,?,?,'queued',?)",
                (task_id, event_id, event, now),
            )
            self.observe_login(db, task_id, json.loads(event))
            self.audit(
                db, now, "event_accepted", "collector", task_id, {"state": "queued"}
            )
        return {"task_id": task_id, "correlation_id": task_id, "state": "queued"}

    def pending(self) -> list[str]:
        with self.connection() as db:
            return [
                row[0]
                for row in db.execute(
                    "SELECT id FROM tasks WHERE state IN ('queued','processing') "
                    "ORDER BY created LIMIT 1000"
                )
            ]

    def process(self, task_id: str, now: float) -> None:
        with self.connection() as db:
            row = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if row is None or row["state"] in ("completed", "failed"):
                return
            observation = db.execute(
                "SELECT failure_count FROM login_observations WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            failure_count = observation["failure_count"]
            if row["state"] == "queued":
                db.execute(
                    "UPDATE tasks SET state = 'processing' WHERE id = ?", (task_id,)
                )
                self.audit(
                    db, now, "processing", "Core", task_id, {"state": "processing"}
                )
        event = json.loads(row["event"])
        success = event["login"]["outcome"] == "success"
        severity = "High" if success else ("Medium" if failure_count >= 5 else "Low")
        evidence_id = str(uuid4())
        evidence = [
            {
                "id": evidence_id,
                "event_id": event["event_id"],
                "raw_record_ref": event["raw_record_ref"],
                "source_kind": "synthetic"
                if event["raw_record_ref"].startswith("synthetic:")
                else "reference_only",
                "facts": {
                    "outcome": event["login"]["outcome"],
                    "protocol": event["protocol"],
                    "cowrie_event_type": event["cowrie_event_type"],
                    "failure_count": failure_count,
                    "window_seconds": 300,
                    "window_basis": "occurred_at",
                    "window_end": event["occurred_at"],
                },
            }
        ]
        verdict = {
            "severity": severity,
            "reason": (
                "Успешный вход в ловушку Cowrie. Признаков вреда вне ловушки нет."
                if success
                else f"Отказ входа в Cowrie; отказов с этого IP за пять минут: "
                f"{failure_count}. Порог Medium — пять отказов."
            ),
            "analysis_method": "Rules",
            "rules_version": "cowrie-login-v2",
            "guard_result": "not_applicable",
            "mitre_attack": None,
            "evidence_ids": [evidence_id],
        }
        with self.connection() as db:
            db.execute(
                "UPDATE tasks SET verdict = ?, evidence = ?, state = 'completed' "
                "WHERE id = ?",
                (json.dumps(verdict), json.dumps(evidence), task_id),
            )
            self.audit(
                db,
                now,
                "verdict_created",
                "Core",
                task_id,
                {"severity": severity, "analysis_method": "Rules"},
            )
            self.audit(db, now, "completed", "Core", task_id, {"state": "completed"})

    def fail(self, task_id: str, now: float, reason: str = "analysis_error") -> None:
        with self.connection() as db:
            db.execute(
                "UPDATE tasks SET state = 'failed' "
                "WHERE id = ? AND state != 'completed'",
                (task_id,),
            )
            self.audit(
                db,
                now,
                "failed",
                "Core",
                task_id,
                {"state": "failed", "reason": reason},
            )

    def task(self, task_id: str) -> dict[str, Any]:
        with self.connection() as db:
            row = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if row is None:
                raise HTTPException(404, "Task not found")
            audit = [
                dict(entry)
                for entry in db.execute(
                    "SELECT * FROM audit WHERE task_id = ? ORDER BY id", (task_id,)
                )
            ]
        for entry in audit:
            entry["details"] = json.loads(entry["details"])
            entry["correlation_id"] = task_id
        return {
            "task_id": task_id,
            "correlation_id": task_id,
            "state": row["state"],
            "event": json.loads(row["event"]),
            "created_at": row["created"],
            "verdict": json.loads(row["verdict"]) if row["verdict"] else None,
            "evidence": json.loads(row["evidence"]) if row["evidence"] else [],
            "history": [
                entry["details"]["state"]
                for entry in audit
                if "state" in entry["details"]
            ],
            "audit": audit,
        }

    def recent(self) -> list[dict[str, Any]]:
        with self.connection() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT id, state, created, verdict FROM tasks "
                    "ORDER BY created DESC, rowid DESC LIMIT 100"
                )
            ]

    def logins(self) -> list[float]:
        with self.connection() as db:
            return [
                row[0]
                for row in db.execute(
                    "SELECT at FROM audit WHERE action = 'login_succeeded' "
                    "ORDER BY id DESC LIMIT 10"
                )
            ]
