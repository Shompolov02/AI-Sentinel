"""Read-only Cowrie input and durable, password-free delivery journal."""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid4, uuid5

from pydantic import BaseModel, IPvAnyAddress, ValidationError

from .contracts import Event, Port, Text

logger = logging.getLogger("ai_sentinel_telemetry")
MAX_LINE = 65536


class Connection(BaseModel):
    session: Text
    src_ip: IPvAnyAddress
    src_port: Port
    dst_port: Port
    protocol: Literal["ssh", "telnet"]


class Journal:
    def __init__(self, database: Path, sensor: str) -> None:
        self.database = database
        self.sensor = sensor
        if not sensor or len(sensor) > 64 or ":" in sensor:
            raise ValueError("Invalid sensor ID")
        database.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS sensor (id TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS files (
                    identity TEXT PRIMARY KEY, generation TEXT NOT NULL,
                    path TEXT NOT NULL, offset INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS connections (
                    session TEXT PRIMARY KEY, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS outbox (
                    id TEXT PRIMARY KEY, payload TEXT NOT NULL,
                    task_id TEXT
                );
                CREATE TABLE IF NOT EXISTS quarantine (
                    reference TEXT PRIMARY KEY, reason TEXT NOT NULL,
                    length INTEGER NOT NULL, digest TEXT NOT NULL
                );
            """)
            prior = db.execute("SELECT id FROM sensor").fetchone()
            if prior and prior[0] != sensor:
                raise ValueError("Collector volume belongs to a different sensor")
            db.execute("INSERT OR IGNORE INTO sensor VALUES (?)", (sensor,))

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.database, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def scan(self, directory: Path) -> None:
        for path in sorted(
            directory.glob("cowrie.json*"), key=lambda p: p.stat().st_mtime
        ):
            if not path.is_file() or path.is_symlink() or path.suffix == ".gz":
                continue
            with path.open("rb") as stream, self.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                first = stream.readline(MAX_LINE + 1)
                if not first or (not first.endswith(b"\n") and len(first) <= MAX_LINE):
                    continue
                stat = path.stat()
                identity = (
                    f"{stat.st_dev}:{stat.st_ino}:" + hashlib.sha256(first).hexdigest()
                )
                row = db.execute(
                    "SELECT generation, offset FROM files WHERE identity = ?",
                    (identity,),
                ).fetchone()
                generation = row["generation"] if row else str(uuid4())
                offset = row["offset"] if row else 0
                if stat.st_size < offset:
                    generation, offset = str(uuid4()), 0
                stream.seek(offset)
                # Bound one poll, while preserving cursor and outbox atomically.
                for _ in range(1000):
                    start = stream.tell()
                    raw = stream.readline(MAX_LINE + 1)
                    if not raw:
                        break
                    if len(raw) > MAX_LINE:
                        digest = hashlib.sha256(raw)
                        length = len(raw)
                        while not raw.endswith(b"\n"):
                            raw = stream.readline(MAX_LINE + 1)
                            if not raw:
                                break
                            digest.update(raw)
                            length += len(raw)
                        if not raw:
                            break  # Even an oversized line can still be in flight.
                        self.quarantine(
                            db,
                            generation,
                            start,
                            b"",
                            "oversize_record",
                            length=length,
                            digest=digest.hexdigest(),
                        )
                    elif not raw.endswith(b"\n"):
                        break  # Writer has not finished this line yet.
                    else:
                        self.record(db, generation, start, raw)
                    offset = stream.tell()
                db.execute(
                    "INSERT OR REPLACE INTO files VALUES (?,?,?,?)",
                    (identity, generation, path.name, offset),
                )

    def record(
        self, db: sqlite3.Connection, generation: str, offset: int, raw: bytes
    ) -> None:
        try:
            record = json.loads(raw)
            if not isinstance(record, dict) or not isinstance(
                record.get("eventid"), str
            ):
                raise ValueError("Invalid record")
            kind = record["eventid"]
            if kind == "cowrie.session.connect":
                connect = Connection.model_validate(record)
                db.execute(
                    "INSERT OR REPLACE INTO connections VALUES (?,?)",
                    (connect.session, connect.model_dump_json()),
                )
                return
            if kind not in ("cowrie.login.failed", "cowrie.login.success"):
                return
            if not isinstance(record.get("session"), str):
                raise ValueError("Invalid session")
            connect_row = db.execute(
                "SELECT payload FROM connections WHERE session = ?",
                (record.get("session"),),
            ).fetchone()
            if connect_row is None or not isinstance(record.get("password"), str):
                raise ValueError("Missing login provenance")
            connect = Connection.model_validate_json(connect_row[0])
            reference = f"cowrie:{self.sensor}:{generation}:{offset}"
            event = Event.model_validate(
                {
                    "schema_version": 1,
                    "event_id": str(uuid5(NAMESPACE_URL, reference)),
                    "occurred_at": record["timestamp"],
                    "received_at": datetime.now(timezone.utc).isoformat(),
                    "event_type": "login_attempt",
                    "cowrie_event_type": kind,
                    "sensor_id": self.sensor,
                    "session_id": connect.session,
                    "source_ip": str(connect.src_ip),
                    "source_port": connect.src_port,
                    "protocol": connect.protocol,
                    "destination_port": connect.dst_port,
                    "raw_record_ref": reference,
                    "login": {
                        "username": record["username"],
                        "outcome": "success"
                        if kind == "cowrie.login.success"
                        else "failure",
                        "password_length": len(record["password"]),
                    },
                }
            )
            db.execute(
                "INSERT OR IGNORE INTO outbox VALUES (?,?,NULL)",
                (str(event.event_id), event.model_dump_json()),
            )
        except (ValueError, KeyError, TypeError, ValidationError, RecursionError):
            self.quarantine(db, generation, offset, raw, "invalid_record")

    def quarantine(
        self,
        db: sqlite3.Connection,
        generation: str,
        offset: int,
        raw: bytes,
        reason: str,
        *,
        length: int | None = None,
        digest: str | None = None,
    ) -> None:
        reference = f"cowrie:{self.sensor}:{generation}:{offset}"
        db.execute(
            "INSERT OR IGNORE INTO quarantine VALUES (?,?,?,?)",
            (
                reference,
                reason,
                len(raw) if length is None else length,
                hashlib.sha256(raw).hexdigest() if digest is None else digest,
            ),
        )
        logger.warning("record_quarantined reference=%s reason=%s", reference, reason)

    def pending(self) -> list[dict[str, Any]]:
        with self.connection() as db:
            return [
                json.loads(row[0])
                for row in db.execute(
                    "SELECT payload FROM outbox WHERE task_id IS NULL "
                    "ORDER BY rowid LIMIT 100"
                )
            ]

    def acknowledge(self, event_id: str, task_id: str) -> None:
        with self.connection() as db:
            db.execute(
                "UPDATE outbox SET task_id = ? WHERE id = ?", (task_id, event_id)
            )

    def status(self) -> dict[str, Any]:
        with self.connection() as db:
            return {
                "files": [dict(row) for row in db.execute("SELECT * FROM files")],
                "quarantine": [
                    dict(row) for row in db.execute("SELECT * FROM quarantine")
                ],
                "deliveries": [
                    dict(row)
                    for row in db.execute(
                        "SELECT id AS event_id, task_id FROM outbox ORDER BY rowid"
                    )
                ],
            }
