"""Read a single Cowrie record without copying raw logs into Core storage."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import secrets
import sqlite3
import ssl
import stat
import time
from collections.abc import Callable
from contextlib import ExitStack, closing
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener
from uuid import NAMESPACE_URL, UUID, uuid5

from fastapi import Depends, FastAPI, HTTPException
from fastapi import Request as WebRequest
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import model_validator

from .compressed_retention import digest_stream
from .contracts import Event
from .storage import TEXT_TTL, file_gate
from .telemetry import MAX_LINE

SourceReader = Callable[[dict[str, Any]], str]


class SourceRequest(Event):
    """An erased event can still query deletion proof without its command."""

    @model_validator(mode="after")
    def matching_outcome(self) -> SourceRequest:
        if (
            self.event_type == "command"
            and self.cowrie_event_type == "cowrie.command.input"
            and self.command is None
            and self.login is None
        ):
            return self
        Event.model_validate(self.model_dump())
        return self


@dataclass(frozen=True)
class ReaderSettings:
    logs: Path
    registry: Path
    tokens: Path
    clock: Callable[[], float] = time.time


def tls_reader(tokens: Path, ca: Path) -> SourceReader:
    context = ssl.create_default_context(cafile=str(ca))
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))

    def read(event: dict[str, Any]) -> str:
        allowed = [line for line in tokens.read_text().splitlines() if line]
        if not allowed:
            raise OSError("Reader credential unavailable")
        request = Request(
            "https://raw-reader:8443/internal/record",
            data=json.dumps(event).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + allowed[-1],
            },
        )
        with opener.open(request, timeout=3) as response:
            content: bytes = response.read(MAX_LINE + 1)
            if response.status != 200 or len(content) > MAX_LINE:
                raise OSError("Invalid reader response")
            return content.decode("utf-8")

    return read


def read_record(settings: ReaderSettings, event: Event) -> str:
    with file_gate(settings.registry, readonly=True):
        return _read_record(settings, event)


def _read_record(settings: ReaderSettings, event: Event) -> str:
    try:
        kind, sensor, generation, position = event.raw_record_ref.split(":")
        if (
            kind != "cowrie"
            or sensor != event.sensor_id
            or str(UUID(generation)) != generation
            or not position.isascii()
            or not position.isdecimal()
            or event.event_id != uuid5(NAMESPACE_URL, event.raw_record_ref)
        ):
            raise ValueError("Invalid source reference")
        offset = int(position)
        with closing(
            sqlite3.connect(settings.registry.resolve().as_uri() + "?mode=ro", uri=True)
        ) as db:
            receipt = db.execute(
                "SELECT state, received FROM source_ranges WHERE reference = ?",
                (event.raw_record_ref,),
            ).fetchone()
            if receipt:
                if receipt[0] == "erased":
                    raise HTTPException(410, "Source deleted")
                if (
                    receipt[0] == "prepared"
                    or receipt[1] is None
                    or settings.clock() >= receipt[1] + TEXT_TTL
                ):
                    raise HTTPException(503, "Source cleanup pending")
            if db.execute("SELECT id FROM sensor").fetchone() != (sensor,):
                raise ValueError("Unknown sensor")
            rows = db.execute(
                "SELECT identity, path FROM files WHERE generation = ?", (generation,)
            ).fetchall()
            pending_archive = (
                db.execute(
                    "SELECT 1 FROM compressed_jobs WHERE generation=? LIMIT 1",
                    (generation,),
                ).fetchone()
                is not None
            )
            archives = db.execute(
                "SELECT device,inode,digest FROM compressed_files "
                "WHERE generation=? AND kind='raw'",
                (generation,),
            ).fetchall()
        if not rows:
            raise HTTPException(404, "Unknown source generation")
        if event.event_type == "command" and event.command is None:
            raise HTTPException(503, "Source cleanup pending")
        directory = os.open(settings.logs, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            names = [
                name for name in os.listdir(directory) if name.startswith("cowrie.json")
            ]
        finally:
            os.close(directory)
        if len(names) > 1000:
            raise HTTPException(503, "Source directory cannot be fully checked")
        uncertain = any(name.endswith(".gz") for name in names)
        registered_names = {row[1] for row in rows}
        replaced = False
        # Search by registered identity, including a rename not yet seen by scan().
        candidates = [
            (row[0], name, False)
            for row in rows
            for name in names
            if not name.endswith(".gz")
        ]
        candidates += [
            (f"{row[0]}:{row[1]}:{row[2]}", name, True)
            for row in archives
            for name in names
            if name.endswith(".gz")
        ]
        for identity, name, compressed in candidates:
            directory = os.open(
                settings.logs, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            try:
                descriptor = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
                )
            except OSError:
                uncertain = True
                continue
            finally:
                os.close(directory)
            with ExitStack() as stack:
                physical = stack.enter_context(os.fdopen(descriptor, "rb"))
                info = os.fstat(physical.fileno())
                if not stat.S_ISREG(info.st_mode):
                    uncertain = True
                    continue
                stream: BinaryIO | gzip.GzipFile
                if compressed:
                    if not identity.startswith(f"{info.st_dev}:{info.st_ino}:"):
                        continue
                    actual = f"{info.st_dev}:{info.st_ino}:" + digest_stream(physical)
                    stream = stack.enter_context(
                        gzip.GzipFile(fileobj=physical, mode="rb")
                    )
                else:
                    stream = physical
                    first = stream.readline(MAX_LINE + 1)
                    actual = (
                        f"{info.st_dev}:{info.st_ino}:"
                        + hashlib.sha256(first).hexdigest()
                    )
                if actual != identity:
                    replaced = replaced or name in registered_names
                    continue
                if not compressed and offset >= info.st_size:
                    raise HTTPException(410, "Source deleted")
                if offset:
                    stream.seek(offset - 1)
                    if stream.read(1) != b"\n":
                        continue
                stream.seek(offset)
                raw = stream.readline(MAX_LINE + 1)
                if len(raw) > MAX_LINE or not raw.endswith(b"\n"):
                    continue
                record = json.loads(raw)
                if (
                    record.get("eventid") != event.cowrie_event_type
                    or record.get("session") != event.session_id
                    or datetime.fromisoformat(
                        record["timestamp"].replace("Z", "+00:00")
                    )
                    != event.occurred_at
                ):
                    continue
                if event.command:
                    if record.get("input") != event.command.text:
                        continue
                elif event.login:
                    password = record.get("password")
                    if (
                        record.get("username") != event.login.username
                        or not isinstance(password, str)
                        or len(password) != event.login.password_length
                    ):
                        continue
                return raw.decode("utf-8")
        if pending_archive:
            raise HTTPException(503, "Source cleanup pending")
        if not uncertain and not replaced:
            raise HTTPException(410, "Source deleted")
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise HTTPException(404, "Source record unavailable") from None
    raise HTTPException(404, "Source record unavailable")


def create_reader_app(settings: ReaderSettings) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(RequestValidationError)
    async def invalid(
        request: WebRequest, error: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse({"detail": "Invalid record request"}, status_code=422)

    @app.middleware("http")
    async def protect_response(request: WebRequest, call_next: Any) -> Any:
        try:
            response = await call_next(request)
        except (OSError, sqlite3.Error):
            response = JSONResponse({"detail": "Source unavailable"}, status_code=503)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    def require_core(request: WebRequest) -> None:
        supplied = request.headers.get("authorization", "").encode()
        if not any(
            secrets.compare_digest(supplied, ("Bearer " + token).encode())
            for token in settings.tokens.read_text().splitlines()
            if token
        ):
            raise HTTPException(401, "Core authorization required")

    @app.post("/internal/record", dependencies=[Depends(require_core)])
    def record(event: SourceRequest) -> PlainTextResponse:
        return PlainTextResponse(read_record(settings, event))

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


def application() -> FastAPI:
    return create_reader_app(
        ReaderSettings(
            Path("/cowrie-logs"),
            Path("/registry/collector.db"),
            Path("/run/secrets/raw-reader-tokens"),
        )
    )
