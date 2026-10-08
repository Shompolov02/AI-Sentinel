from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from target_app.surfaces import PingTimedOut, run_ping, search_assets

BASE_DIR = Path(__file__).resolve().parent
MAX_INPUT_LENGTH = 4096
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "correlation_id": getattr(record, "correlation_id", None),
            "client_ip": getattr(record, "client_ip", None),
            "method": getattr(record, "method", None),
            "path": getattr(record, "path", None),
            "status": getattr(record, "status", None),
            "duration_ms": getattr(record, "duration_ms", None),
        }
        if hasattr(record, "event"):
            payload["event"] = record.event
        if hasattr(record, "text"):
            payload["text"] = record.text
        return json.dumps(payload, separators=(",", ":"))


logger = logging.getLogger("target_app")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
logger.propagate = False


class SecurityAndCorrelationMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        started = time.perf_counter()
        # The Compose network contains only this app and the edge, which overwrites
        # client forwarding headers. Direct application runs keep their own ID.
        trusted_edge = os.environ.get("TRUST_NGINX_HEADERS") == "1"
        incoming_id = request.headers.get("x-request-id", "")
        edge_id_is_valid = re.fullmatch(r"[0-9a-f]{32}", incoming_id) is not None
        correlation_id = (
            incoming_id if trusted_edge and edge_id_is_valid else str(uuid.uuid4())
        )
        request.state.correlation_id = correlation_id
        peer_ip = request.client.host if request.client is not None else "unknown"
        client_ip = (
            request.headers.get("x-real-ip", peer_ip) if trusted_edge else peer_ip
        )
        try:
            response = await call_next(request)
        except Exception:
            response = error_response(correlation_id, 500)
        response.headers["X-Request-ID"] = correlation_id
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        logger.info(
            "request",
            extra={
                "correlation_id": correlation_id,
                "client_ip": client_ip,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            },
        )
        return response


def error_response(correlation_id: str, status: int) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "error": "Request could not be processed",
            "correlation_id": correlation_id,
            "status": status,
        },
    )


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class PingRequest(InputModel):
    target: Annotated[str, Field(min_length=1, max_length=MAX_INPUT_LENGTH)]


class SearchRequest(InputModel):
    query: Annotated[str, Field(min_length=1, max_length=MAX_INPUT_LENGTH)]


class AnalyzeRequest(InputModel):
    text: Annotated[str, Field(min_length=1, max_length=MAX_INPUT_LENGTH)]


class Asset(BaseModel):
    id: int
    hostname: str
    ip_address: str
    status: str
    description: str


class SearchResult(BaseModel):
    status: str
    query: str
    results: list[Asset]
    correlation_id: str


class PingResult(BaseModel):
    status: str
    target: str
    stdout: str
    stderr: str
    exit_code: int
    truncated: bool
    correlation_id: str


class AnalyzeResult(BaseModel):
    status: str
    correlation_id: str


def correlated(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    return {**payload, "correlation_id": request.state.correlation_id}


class TargetApp(FastAPI):
    def openapi(self) -> dict[str, Any]:
        if self.openapi_schema is not None:
            return self.openapi_schema
        schema = get_openapi(
            title=self.title,
            version=self.version,
            description=self.description,
            routes=self.routes,
        )
        for path in schema["paths"].values():
            for operation in path.values():
                operation.get("responses", {}).pop("422", None)
        self.openapi_schema = schema
        return schema


app = TargetApp(
    title="AI-Sentinel — целевое приложение",
    description="Учебное уязвимое приложение для лабораторных испытаний.",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
)
app.add_middleware(SecurityAndCorrelationMiddleware)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.get("/docs", include_in_schema=False)
async def swagger_docs(request: Request) -> Response:
    return templates.TemplateResponse(request=request, name="docs.html")


@app.get("/redoc", include_in_schema=False)
async def redoc_docs(request: Request) -> Response:
    return templates.TemplateResponse(request=request, name="redoc.html")


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request, _exc: RequestValidationError
) -> JSONResponse:
    return error_response(request.state.correlation_id, 400)


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    return error_response(request.state.correlation_id, exc.status_code)


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, _exc: Exception) -> JSONResponse:
    return error_response(request.state.correlation_id, 500)


@app.get("/", include_in_schema=False)
async def dashboard(request: Request) -> Response:
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"correlation_id": request.state.correlation_id},
    )


@app.get("/health", summary="Проверка состояния")
async def health(request: Request) -> dict[str, str]:
    return correlated({"status": "ok"}, request)


@app.post(
    "/api/diagnostics/ping",
    summary="Сетевая диагностика",
    response_model=PingResult,
    responses={
        400: {"description": "Некорректный запрос"},
        504: {"description": "Превышено время выполнения"},
    },
)
async def diagnostics_ping(
    payload: PingRequest, request: Request
) -> PingResult | JSONResponse:
    try:
        output = await asyncio.to_thread(run_ping, payload.target)
    except PingTimedOut:
        return error_response(request.state.correlation_id, 504)
    return PingResult(
        status="completed",
        target=payload.target,
        stdout=output.stdout,
        stderr=output.stderr,
        exit_code=output.exit_code,
        truncated=output.truncated,
        correlation_id=request.state.correlation_id,
    )


def search_response(query: str, request: Request) -> SearchResult | JSONResponse:
    normalized = query.strip()
    if not normalized:
        return error_response(request.state.correlation_id, 400)
    try:
        assets = search_assets(normalized)
    except sqlite3.OperationalError:
        return error_response(request.state.correlation_id, 400)
    return SearchResult(
        status="ok",
        query=normalized,
        results=[Asset.model_validate(asset) for asset in assets],
        correlation_id=request.state.correlation_id,
    )


@app.get(
    "/search",
    summary="Поиск учебных активов",
    response_model=SearchResult,
    responses={400: {"description": "Некорректный запрос"}},
)
async def search_page(
    request: Request,
    q: Annotated[str, Query(min_length=1, max_length=MAX_INPUT_LENGTH)],
) -> SearchResult | JSONResponse:
    return search_response(q, request)


@app.post(
    "/api/search",
    summary="Поиск активов",
    response_model=SearchResult,
    responses={400: {"description": "Некорректный запрос"}},
)
async def search(
    payload: SearchRequest, request: Request
) -> SearchResult | JSONResponse:
    return search_response(payload.query, request)


@app.post(
    "/api/analyze",
    summary="Приём события безопасности",
    response_model=AnalyzeResult,
    responses={400: {"description": "Некорректный запрос"}},
)
async def analyze(payload: AnalyzeRequest, request: Request) -> AnalyzeResult:
    logger.info(
        "prompt input received",
        extra={
            "event": "PROMPT_INPUT_RECEIVED",
            "status": "RECEIVED",
            "correlation_id": request.state.correlation_id,
            "text": payload.text,
        },
    )
    return AnalyzeResult(status="RECEIVED", correlation_id=request.state.correlation_id)
