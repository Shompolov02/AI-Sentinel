from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import HTTPException

from .guard import POLICY_VERSION, Guard
from .storage import METADATA_TTL, TEXT_TTL, connect, text_expired

logger = logging.getLogger("ai_sentinel_core")


class Store:
    def __init__(
        self,
        path: Path,
        guard_model: Path | None = None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = path
        self.clock = clock
        self.guard = Guard(guard_model)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            legacy_sessions = (
                db.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'session_roles'"
                ).fetchone()
                is None
            )
            db.executescript("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY, event_id TEXT UNIQUE NOT NULL,
                    event TEXT NOT NULL, state TEXT NOT NULL,
                    created REAL NOT NULL, verdict TEXT, evidence TEXT
                );
                CREATE TABLE IF NOT EXISTS task_analysis (
                    task_id TEXT PRIMARY KEY, payload TEXT NOT NULL
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
                CREATE TABLE IF NOT EXISTS session_roles (
                    digest TEXT PRIMARY KEY, role TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS source_deletions (
                    event_id TEXT PRIMARY KEY, confirmed_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY, at REAL NOT NULL,
                    action TEXT NOT NULL, actor TEXT NOT NULL,
                    task_id TEXT, details TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS core_alerts (
                    id TEXT PRIMARY KEY, at REAL NOT NULL, code TEXT NOT NULL,
                    task_id TEXT, resolved_at REAL
                );
                CREATE TABLE IF NOT EXISTS retained_events (
                    task_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
                    text_expires REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS task_retention (
                    task_id TEXT PRIMARY KEY, expires REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS command_text (
                    task_id TEXT PRIMARY KEY, text TEXT NOT NULL,
                    expires REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS retention_meta (id INTEGER PRIMARY KEY);
            """)
            scrub_legacy = db.execute("SELECT 1 FROM retention_meta").fetchone() is None
            # Upgrade the accepted-event history without revisiting old verdicts.
            db.execute("BEGIN IMMEDIATE")
            if legacy_sessions:
                # Before #49 every human session belonged to the sole SecOps.
                db.execute(
                    "INSERT INTO session_roles SELECT digest, 'SecOps' FROM sessions"
                )
            for row in db.execute(
                "SELECT t.id, t.event FROM tasks t LEFT JOIN login_observations o "
                "ON o.task_id = t.id WHERE o.task_id IS NULL ORDER BY t.rowid"
            ).fetchall():
                self.observe_login(db, row["id"], json.loads(row["event"]))
            for row in db.execute(
                "SELECT id, event FROM tasks WHERE id NOT IN "
                "(SELECT task_id FROM retained_events)"
            ).fetchall():
                self.retain_event(db, row["id"], row["event"])
            for row in db.execute(
                "SELECT id, event, created FROM tasks WHERE id NOT IN "
                "(SELECT task_id FROM task_retention)"
            ).fetchall():
                self.retain_metadata(db, row["id"], row["event"], row["created"])
        self.expire_text(self.clock())
        self.expire_metadata(self.clock())
        if scrub_legacy:
            with self.connection() as db:
                db.execute("VACUUM")
                db.execute("INSERT OR IGNORE INTO retention_meta VALUES (1)")

    def retain_event(self, db: sqlite3.Connection, task_id: str, payload: str) -> str:
        event = json.loads(payload)
        try:
            expires = (
                datetime.fromisoformat(
                    event["received_at"].replace("Z", "+00:00")
                ).timestamp()
                + TEXT_TTL
            )
        except (KeyError, ValueError, TypeError, AttributeError):
            # Unknown historical text must not acquire a new lifetime.
            expires = self.clock()
        db.execute(
            "INSERT INTO retained_events VALUES (?,?,?)",
            (task_id, hashlib.sha256(payload.encode()).hexdigest(), expires),
        )
        if event["event_type"] == "command":
            db.execute(
                "INSERT INTO command_text VALUES (?,?,?)",
                (
                    task_id,
                    event["command"]["text"],
                    expires,
                ),
            )
            event["command"]["text"] = None
            payload = json.dumps(event, sort_keys=True)
            db.execute("UPDATE tasks SET event = ? WHERE id = ?", (payload, task_id))
        return payload

    @staticmethod
    def retain_metadata(
        db: sqlite3.Connection, task_id: str, payload: str, created: float
    ) -> None:
        event = json.loads(payload)
        try:
            received = datetime.fromisoformat(
                event["received_at"].replace("Z", "+00:00")
            ).timestamp()
        except (KeyError, ValueError, TypeError, AttributeError):
            # Legacy Core admission is known even when telemetry receipt is not.
            received = created
        db.execute(
            "INSERT INTO task_retention VALUES (?,?)",
            (task_id, received + METADATA_TTL),
        )

    def expire_metadata(self, now: float) -> None:
        with self.connection() as db:
            if (
                db.execute(
                    "SELECT 1 FROM task_retention WHERE expires <= ? "
                    "UNION ALL SELECT 1 FROM audit WHERE at <= ? "
                    "UNION ALL SELECT 1 FROM core_alerts WHERE at <= ? LIMIT 1",
                    (now, now - METADATA_TTL, now - METADATA_TTL),
                ).fetchone()
                is None
            ):
                return
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "DELETE FROM source_deletions WHERE event_id IN "
                "(SELECT event_id FROM tasks WHERE id IN "
                "(SELECT task_id FROM task_retention WHERE expires <= ?))",
                (now,),
            )
            statements = (
                "DELETE FROM command_text WHERE task_id IN "
                "(SELECT task_id FROM task_retention WHERE expires <= ?)",
                "DELETE FROM task_analysis WHERE task_id IN "
                "(SELECT task_id FROM task_retention WHERE expires <= ?)",
                "DELETE FROM login_observations WHERE task_id IN "
                "(SELECT task_id FROM task_retention WHERE expires <= ?)",
                "DELETE FROM retained_events WHERE task_id IN "
                "(SELECT task_id FROM task_retention WHERE expires <= ?)",
                "DELETE FROM audit WHERE task_id IN "
                "(SELECT task_id FROM task_retention WHERE expires <= ?)",
                "DELETE FROM core_alerts WHERE task_id IN "
                "(SELECT task_id FROM task_retention WHERE expires <= ?)",
                "DELETE FROM tasks WHERE id IN "
                "(SELECT task_id FROM task_retention WHERE expires <= ?)",
            )
            for statement in statements:
                db.execute(statement, (now,))
            db.execute("DELETE FROM task_retention WHERE expires <= ?", (now,))
            db.execute("DELETE FROM audit WHERE at <= ?", (now - METADATA_TTL,))
            db.execute("DELETE FROM core_alerts WHERE at <= ?", (now - METADATA_TTL,))

    def expire_text(self, now: float) -> None:
        with self.connection() as db:
            if (
                db.execute(
                    "SELECT 1 FROM command_text WHERE expires <= ? LIMIT 1", (now,)
                ).fetchone()
                is None
            ):
                return
            db.execute("DELETE FROM command_text WHERE expires <= ?", (now,))

    @staticmethod
    def observe_login(
        db: sqlite3.Connection, task_id: str, event: dict[str, Any]
    ) -> None:
        if event["event_type"] != "login_attempt":
            return
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
        db = connect(self.path)
        try:
            with db:
                yield db
        finally:
            db.close()

    def login(self, digest: str, now: float, role: str = "SecOps") -> None:
        with self.connection() as db:
            db.execute("INSERT INTO sessions VALUES (?, ?)", (digest, now))
            db.execute("INSERT INTO session_roles VALUES (?, ?)", (digest, role))
            self.audit(db, now, "login_succeeded", role, None, {})

    def authenticate(self, digest: str, now: float, touch: bool = True) -> str | None:
        with self.connection() as db:
            db.execute("DELETE FROM sessions WHERE last_active <= ?", (now - 1800,))
            db.execute(
                "DELETE FROM session_roles "
                "WHERE digest NOT IN (SELECT digest FROM sessions)"
            )
            row = db.execute(
                "SELECT role FROM sessions JOIN session_roles USING (digest) "
                "WHERE digest = ?",
                (digest,),
            ).fetchone()
            if row is None:
                return None
            if touch:
                db.execute(
                    "UPDATE sessions SET last_active = ? WHERE digest = ?",
                    (now, digest),
                )
            return str(row["role"])

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

    def source_deleted(self, event_id: str) -> bool:
        with self.connection() as db:
            return (
                db.execute(
                    "SELECT 1 FROM source_deletions WHERE event_id = ?", (event_id,)
                ).fetchone()
                is not None
            )

    def confirm_source_deleted(self, event_id: str, now: float) -> None:
        with self.connection() as db:
            db.execute(
                "INSERT OR IGNORE INTO source_deletions "
                "SELECT ?, ? WHERE EXISTS (SELECT 1 FROM tasks t "
                "JOIN task_retention r ON r.task_id=t.id "
                "WHERE t.event_id=? AND r.expires>?)",
                (event_id, now, event_id, self.clock()),
            )

    def accept(self, event: str, event_id: str, now: float) -> dict[str, str]:
        self.expire_metadata(now)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute(
                "SELECT * FROM tasks WHERE event_id = ?", (event_id,)
            ).fetchone()
            if prior:
                fingerprint = db.execute(
                    "SELECT fingerprint FROM retained_events WHERE task_id = ?",
                    (prior["id"],),
                ).fetchone()[0]
                if fingerprint != hashlib.sha256(event.encode()).hexdigest():
                    raise HTTPException(409, "Event ID content conflict")
                return {
                    "task_id": prior["id"],
                    "correlation_id": prior["id"],
                    "state": prior["state"],
                }
            if text_expired(json.loads(event), now):
                raise HTTPException(410, "Source retention period expired")
            count = db.execute(
                "SELECT count(*) FROM tasks WHERE state IN ('queued','processing')"
            ).fetchone()[0]
            if count >= 1000:
                logger.critical("intake_capacity_reached")
                raise HTTPException(503, "Intake capacity reached; retry later")
            task_id = str(uuid4())
            db.execute(
                "INSERT INTO tasks (id,event_id,event,state,created) "
                "VALUES (?,?,?,'queued',?)",
                (task_id, event_id, event, now),
            )
            self.observe_login(db, task_id, json.loads(event))
            self.retain_event(db, task_id, event)
            self.retain_metadata(db, task_id, event, now)
            self.audit(
                db, now, "event_accepted", "collector", task_id, {"state": "queued"}
            )
        return {"task_id": task_id, "correlation_id": task_id, "state": "queued"}

    def pending(self) -> list[str]:
        self.expire_metadata(self.clock())
        with self.connection() as db:
            return [
                row[0]
                for row in db.execute(
                    "SELECT id FROM tasks WHERE state IN ('queued','processing') "
                    "ORDER BY created LIMIT 1000"
                )
            ]

    def intake_full(self) -> bool:
        return self.intake_depth() >= 1000

    def intake_depth(self) -> int:
        with self.connection() as db:
            return int(
                db.execute(
                    "SELECT count(*) FROM tasks WHERE state IN ('queued','processing')"
                ).fetchone()[0]
            )

    def process(self, task_id: str, now: float) -> None:
        self.expire_text(self.clock())
        self.expire_metadata(self.clock())
        with self.connection() as db:
            row = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if row is None or row["state"] in ("completed", "failed"):
                return
            event = json.loads(row["event"])
            text = db.execute(
                "SELECT text FROM command_text WHERE task_id = ?", (task_id,)
            ).fetchone()
            if event["event_type"] == "command" and text is not None:
                event["command"]["text"] = text[0]
            observation = db.execute(
                "SELECT failure_count FROM login_observations WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            failure_count = observation["failure_count"] if observation else 0
            if row["state"] == "queued":
                db.execute(
                    "UPDATE tasks SET state = 'processing' WHERE id = ?", (task_id,)
                )
                self.audit(
                    db, now, "processing", "Core", task_id, {"state": "processing"}
                )
        if event["event_type"] == "command":
            self.process_command(task_id, event, now)
            return
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
            db.execute("BEGIN IMMEDIATE")
            if not self.live_task(db, task_id):
                return
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

    def live_task(self, db: sqlite3.Connection, task_id: str) -> bool:
        return (
            db.execute(
                "SELECT 1 FROM tasks t JOIN task_retention r ON r.task_id=t.id "
                "WHERE t.id=? AND r.expires>?",
                (task_id, self.clock()),
            ).fetchone()
            is not None
        )

    def process_command(self, task_id: str, event: dict[str, Any], now: float) -> None:
        evidence_id = str(uuid4())
        expired = event["command"]["text"] is None or text_expired(event, self.clock())
        guard = (
            {
                "status": "error",
                "score": None,
                "reason_code": "text_expired",
                "model_id": None,
                "revision": None,
                "threshold": None,
            }
            if expired
            else self.guard.inspect(event["command"]["text"])
        )
        if not expired and text_expired(event, self.clock()):
            self.process_command(task_id, {**event, "command": {"text": None}}, now)
            return
        blocked = guard["status"] == "blocked"
        if expired:
            reason_code = "text_expired"
            reason = (
                "Срок хранения текста истёк; оставшихся данных недостаточно для оценки."
            )
        elif blocked:
            reason_code = "prompt_injection_detected"
            reason = (
                "Экспериментальный Prompt Guard обнаружил признаки Prompt Injection. "
                "Текст изолирован от LLM."
            )
        elif guard["status"] == "no_match":
            reason_code = "insufficient_rules"
            reason = (
                "Недостаточно резервных правил для оценки команды. "
                "Prompt Guard не обнаружил признаков Prompt Injection; "
                "LLM не подключена, оценка невозможна."
            )
        else:
            reason_code = "guard_unavailable"
            reason = (
                "Prompt Guard недоступен. Внешний вызов запрещён; оценка невозможна."
            )
        analysis: dict[str, Any] = {
            "analysis_method": "Fallback",
            "rules_version": POLICY_VERSION,
            "guard_result": guard,
            "reason_code": reason_code,
            "reason": reason,
            "mitre_attack": None,
            "evidence_ids": [evidence_id],
        }
        evidence = [
            {
                "id": evidence_id,
                "event_id": event["event_id"],
                "raw_record_ref": event["raw_record_ref"],
                "source_kind": "synthetic"
                if event["raw_record_ref"].startswith("synthetic:")
                else "reference_only",
                "facts": {
                    "cowrie_event_type": event["cowrie_event_type"],
                    "protocol": event["protocol"],
                    "guard_result": analysis["guard_result"],
                },
            }
        ]
        state = "completed" if blocked else "failed"
        verdict = {**analysis, "severity": "High"} if blocked else None
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if not self.live_task(db, task_id):
                return
            if not expired and text_expired(event, self.clock()):
                # Waiting for SQLite's writer may cross the text deadline.
                db.rollback()
                self.process_command(task_id, {**event, "command": {"text": None}}, now)
                return
            db.execute(
                "INSERT OR REPLACE INTO task_analysis VALUES (?,?)",
                (task_id, json.dumps(analysis)),
            )
            db.execute(
                "UPDATE tasks SET state = ?, evidence = ?, verdict = ? WHERE id = ?",
                (
                    state,
                    json.dumps(evidence),
                    json.dumps(verdict) if verdict else None,
                    task_id,
                ),
            )
            self.audit(
                db, now, "guard_checked", "Core", task_id, analysis["guard_result"]
            )
            self.audit(
                db,
                now,
                "fallback_warning",
                "Core",
                task_id,
                {"reason_code": analysis["reason_code"]},
            )
            if verdict:
                self.audit(
                    db,
                    now,
                    "verdict_created",
                    "Core",
                    task_id,
                    {"severity": "High", "analysis_method": "Fallback"},
                )
            self.audit(
                db,
                now,
                state,
                "Core",
                task_id,
                {"state": state, "reason": analysis["reason_code"]},
            )
        logger.warning(
            "command_fallback task_id=%s reason=%s", task_id, analysis["reason_code"]
        )

    def fail(self, task_id: str, now: float, reason: str = "analysis_error") -> None:
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if not self.live_task(db, task_id):
                return
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
        self.expire_text(self.clock())
        self.expire_metadata(self.clock())
        with self.connection() as db:
            row = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if row is None:
                raise HTTPException(404, "Task not found")
            event = json.loads(row["event"])
            text = db.execute(
                "SELECT text FROM command_text WHERE task_id = ?", (task_id,)
            ).fetchone()
            if event["event_type"] == "command" and text is not None:
                event["command"]["text"] = text[0]
            analysis = db.execute(
                "SELECT payload FROM task_analysis WHERE task_id = ?", (task_id,)
            ).fetchone()
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
            "event": event,
            "created_at": row["created"],
            "verdict": json.loads(row["verdict"]) if row["verdict"] else None,
            "analysis": json.loads(analysis["payload"]) if analysis else None,
            "evidence": json.loads(row["evidence"]) if row["evidence"] else [],
            "history": [
                entry["details"]["state"]
                for entry in audit
                if "state" in entry["details"]
            ],
            "audit": audit,
        }

    def recent(self, q: str = "", state: str = "") -> list[dict[str, Any]]:
        self.expire_metadata(self.clock())
        with self.connection() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT id, state, created, verdict, "
                    "json_extract(event, '$.event_type') AS event_type, "
                    "json_extract(event, '$.login.outcome') AS outcome FROM tasks "
                    "WHERE (? = '' OR state = ?) "
                    "AND instr(lower(id), lower(?)) > 0 "
                    "ORDER BY created DESC, rowid DESC LIMIT 100",
                    (state, state, q),
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

    def alert_history(self) -> list[dict[str, Any]]:
        with self.connection() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT at, task_id, level, code, resolved_at FROM ("
                    "SELECT at, task_id, 'warning' AS level, "
                    "CASE WHEN action = 'failed' THEN 'analysis_error' "
                    "ELSE json_extract(details, '$.reason_code') END AS code, "
                    "NULL AS resolved_at, id AS ordinal, 0 AS source FROM audit "
                    "WHERE action = 'fallback_warning' OR "
                    "(action = 'failed' AND "
                    "json_extract(details, '$.reason') = 'analysis_error') "
                    "UNION ALL SELECT at, task_id, 'critical', code, "
                    "resolved_at, rowid, 1 "
                    "FROM core_alerts) "
                    "ORDER BY at DESC, source DESC, ordinal DESC LIMIT 100"
                )
            ]
