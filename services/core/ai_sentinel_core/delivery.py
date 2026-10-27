"""Loopback Fluent Bit output; only Core's durable receipt acknowledges input."""

from __future__ import annotations

import json
import logging
import sqlite3
import ssl
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, cast
from urllib.error import URLError
from urllib.request import Request, urlopen
from uuid import UUID

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import Field

from .contracts import Event
from .storage import file_gate, text_expired
from .telemetry import Journal

logger = logging.getLogger("ai_sentinel_telemetry")
Sender = Callable[[dict[str, Any]], dict[str, str]]


def tls_sender(tokens: Path, ca: Path) -> Sender:
    context = ssl.create_default_context(cafile=str(ca))

    def send(event: dict[str, Any]) -> dict[str, str]:
        # Read each request so manual token rotation does not require embedding
        # a credential in Fluent Bit's configuration or environment.
        allowed = [line for line in tokens.read_text().splitlines() if line]
        if not allowed:
            raise ValueError("Collector token unavailable")
        token = allowed[-1]
        request = Request(
            "https://core-intake:8443/internal/events",
            data=json.dumps(event, ensure_ascii=False).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token,
            },
        )
        with urlopen(request, context=context, timeout=5) as response:  # noqa: S310
            if response.status != 202:
                raise ValueError("Core did not acknowledge delivery")
            receipt = json.load(response)
        UUID(receipt["task_id"])
        return cast(dict[str, str], receipt)

    return send


def create_delivery_app(journal: Journal, send: Sender) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Any, error: RequestValidationError) -> JSONResponse:
        return JSONResponse({"detail": "Invalid normalized batch"}, status_code=422)

    @app.post("/deliver")
    def deliver(
        events: Annotated[list[Event], Field(max_length=1000)],
    ) -> dict[str, Any]:
        receipts = []
        try:
            with file_gate(journal.database.parent / "buffer"):
                for event in events:
                    payload = event.model_dump(mode="json", exclude_none=True)
                    if text_expired(payload, journal.clock()):
                        raise HTTPException(410, "Buffered source expired")
                    receipt = send(payload)
                    journal.acknowledge(str(event.event_id), receipt["task_id"])
                    receipts.append(receipt)
        except (OSError, URLError, sqlite3.Error, ValueError, KeyError) as error:
            logger.warning(
                "core_delivery_unavailable reason=%s status=%s retry_pending=true",
                type(error).__name__,
                getattr(error, "code", "none"),
            )
            raise HTTPException(503, "Delivery pending; retry") from None
        return {"receipts": receipts}

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
