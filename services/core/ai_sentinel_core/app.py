from __future__ import annotations

import asyncio
import json
import logging
import secrets
import sqlite3
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from starlette.responses import Response

from . import pages
from .auth import session_digest, verify_password
from .contracts import Event
from .store import Store

logger = logging.getLogger("ai_sentinel_core")


@dataclass(frozen=True)
class Settings:
    database: Path
    tokens: Path
    password_hash: Path
    clock: Callable[[], float] = time.time


class LoginRequest(BaseModel):
    password: str = Field(max_length=4096)


def create_app(settings: Settings) -> FastAPI:
    store = Store(settings.database)
    queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1000)
    scheduled: set[str] = set()

    def schedule(task_id: str) -> None:
        if task_id not in scheduled:
            queue.put_nowait(task_id)
            scheduled.add(task_id)

    async def worker() -> None:
        while True:
            task_id = await queue.get()
            try:
                work = asyncio.create_task(
                    asyncio.to_thread(store.process, task_id, settings.clock())
                )
                try:
                    await asyncio.shield(work)
                except asyncio.CancelledError:
                    # Finish the current commit before releasing the worker;
                    # remaining queued tasks stay durable for next startup.
                    await work
                    raise
            except Exception:
                logger.error("analysis_error task_id=%s", task_id)
                try:
                    store.fail(task_id, settings.clock())
                except Exception:
                    logger.critical("storage_failure task_id=%s", task_id)
            finally:
                scheduled.discard(task_id)
                queue.task_done()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        for task_id in store.pending():
            schedule(task_id)
        runner = asyncio.create_task(worker())
        try:
            yield
        finally:
            runner.cancel()
            with suppress(asyncio.CancelledError):
                await runner

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def session_cookie(
        request: Request, call_next: Callable[[Request], Any]
    ) -> Response:
        try:
            response: Response = await call_next(request)
        except (sqlite3.Error, OSError):
            logger.critical("storage_unavailable")
            response = JSONResponse(
                {"detail": "Storage unavailable; retry later"}, status_code=503
            )
        if response.status_code == 401 and request.url.path.startswith("/tasks"):
            response = HTMLResponse(
                '<html lang="ru"><meta charset="utf-8">'
                "<h1>Требуется вход SecOps</h1>"
                "<p>Сеанс отсутствует или окончен.</p>"
                '<a href="/login">Войти</a></html>',
                status_code=401,
            )
        token = getattr(request.state, "active_session", None)
        if token:
            response.set_cookie(
                "core_session", token, httponly=True, samesite="strict", max_age=1800
            )
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; "
            "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; "
            "base-uri 'none'"
        )
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_event(
        request: Request, error: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse({"detail": "Invalid request"}, status_code=422)

    def require_collector(request: Request) -> None:
        supplied = request.headers.get("authorization", "")
        allowed = settings.tokens.read_text().splitlines()
        if not any(
            secrets.compare_digest(supplied.encode(), ("Bearer " + token).encode())
            for token in allowed
            if token
        ):
            raise HTTPException(401, "Collector authorization required")

    def require_secops(request: Request) -> None:
        token = request.cookies.get("core_session", "")
        touch = request.query_params.get("poll") != "1"
        if not token or not store.authenticate(
            session_digest(token), settings.clock(), touch
        ):
            raise HTTPException(401, "SecOps login required")
        if touch:
            request.state.active_session = token

    @app.post(
        "/internal/events", status_code=202, dependencies=[Depends(require_collector)]
    )
    async def receive(payload: Event) -> dict[str, str]:
        result = store.accept(
            json.dumps(payload.model_dump(mode="json"), sort_keys=True),
            str(payload.event_id),
            settings.clock(),
        )
        if result["state"] in ("queued", "processing"):
            schedule(result["task_id"])
        return result

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/login")
    def login(payload: LoginRequest) -> JSONResponse:
        if not verify_password(payload.password, settings.password_hash.read_text()):
            raise HTTPException(401, "Invalid credentials")
        token = secrets.token_urlsafe(32)
        store.login(session_digest(token), settings.clock())
        response = JSONResponse({"role": "SecOps"})
        response.set_cookie(
            "core_session", token, httponly=True, samesite="strict", max_age=1800
        )
        return response

    @app.get(
        "/tasks", response_class=HTMLResponse, dependencies=[Depends(require_secops)]
    )
    def tasks() -> str:
        return pages.task_list(store.recent(), store.logins())

    @app.get("/api/tasks/{task_id}", dependencies=[Depends(require_secops)])
    def task(task_id: str) -> dict[str, Any]:
        return store.task(task_id)

    @app.get(
        "/tasks/{task_id}",
        response_class=HTMLResponse,
        dependencies=[Depends(require_secops)],
    )
    def task_page(task_id: str) -> str:
        return pages.task_page(store.task(task_id))

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse("/login")

    @app.get("/login", response_class=HTMLResponse)
    def login_page() -> str:
        return pages.login_page()

    @app.get("/login.js")
    def login_script() -> Response:
        return Response(pages.LOGIN_SCRIPT, media_type="text/javascript")

    return app
