"""Read a single Cowrie record without copying raw logs into Core storage."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import ssl
import stat
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener
from uuid import NAMESPACE_URL, UUID, uuid5

from fastapi import Depends, FastAPI, HTTPException
from fastapi import Request as WebRequest
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse

from .contracts import Event
from .telemetry import MAX_LINE

SourceReader = Callable[[dict[str, Any]], str]


@dataclass(frozen=True)
class ReaderSettings:
    logs: Path
    registry: Path
    tokens: Path


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
            if db.execute("SELECT id FROM sensor").fetchone() != (sensor,):
                raise ValueError("Unknown sensor")
            rows = db.execute(
                "SELECT identity, path FROM files WHERE generation = ?", (generation,)
            ).fetchall()
        if not rows:
            raise HTTPException(404, "Unknown source generation")
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
            (row[0], name) for row in rows for name in names if not name.endswith(".gz")
        ]
        for identity, name in candidates:
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
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    uncertain = True
                    continue
                first = stream.readline(MAX_LINE + 1)
                actual = (
                    f"{info.st_dev}:{info.st_ino}:" + hashlib.sha256(first).hexdigest()
                )
                if actual != identity:
                    replaced = replaced or name in registered_names
                    continue
                if offset >= info.st_size:
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
    def record(event: Event) -> PlainTextResponse:
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
