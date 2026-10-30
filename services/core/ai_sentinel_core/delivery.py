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

from .backpressure import Pressure
from .buffer_retention import buffer_gate
from .contracts import Event
from .storage import text_expired
from .telemetry import Journal

logger = logging.getLogger("ai_sentinel_telemetry")
Sender = Callable[[dict[str, Any]], dict[str, str]]


def tls_capacity(tokens: Path, ca: Path) -> Callable[[], int]:
    context = ssl.create_default_context(cafile=str(ca))

    def depth() -> int:
        token = [line for line in tokens.read_text().splitlines() if line][-1]
        request = Request(
            "https://core-intake:8443/internal/events",
            method="HEAD",
            headers={"Authorization": "Bearer " + token},
        )
        with urlopen(request, context=context, timeout=5) as response:  # noqa: S310
            return int(response.headers["X-Core-Queue-Depth"])

    return depth


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
            depth = response.headers.get("X-Core-Queue-Depth")
            if depth is not None:
                receipt["queue_depth"] = depth
        UUID(receipt["task_id"])
        return cast(dict[str, str], receipt)

    return send


def create_delivery_app(
    journal: Journal, send: Sender, *, pressure: Pressure | None = None
) -> FastAPI:
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
            with buffer_gate(journal.database.parent):
                for event in events:
                    payload = event.model_dump(mode="json", exclude_none=True)
                    if text_expired(payload, journal.clock()):
                        # Retry until the owner stops Fluent Bit and scrubs its
                        # chunks. A terminal 4xx could discard a mixed chunk
                        # before its expired bytes are physically truncated.
                        raise HTTPException(503, "Expired buffer cleanup pending")
                    receipt = send(payload)
                    depth = receipt.pop("queue_depth", None)
                    if pressure is not None and depth is not None:
                        pressure.core_depth(int(depth))
                    journal.acknowledge(str(event.event_id), receipt["task_id"])
                    receipts.append(receipt)
        except (OSError, URLError, sqlite3.Error, ValueError, KeyError) as error:
            if (
                pressure is not None
                and getattr(error, "code", None) == 503
                and getattr(error, "headers", {}).get("X-Core-Queue-Depth") == "1000"
            ):
                pressure.core_depth(1000)
            logger.warning(
                "core_delivery_unavailable reason=%s status=%s retry_pending=true",
                type(error).__name__,
                getattr(error, "code", "none"),
            )
            raise HTTPException(503, "Delivery pending; retry") from None
        return {"receipts": receipts}

    @app.get("/health")
    def health() -> dict[str, Any]:
        return pressure.snapshot() if pressure is not None else {"status": "ok"}

    return app
