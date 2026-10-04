from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

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
        # Nginx overwrites this header at ingress; direct client values are untrusted.
        correlation_id = str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        client_ip = request.headers.get("x-real-ip", "unknown")
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


def correlated(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    return {**payload, "correlation_id": request.state.correlation_id}


app = FastAPI(
    title="AI-Sentinel Target App",
    description="Intentionally vulnerable target for controlled laboratory testing.",
    version="1.0.0",
)
app.add_middleware(SecurityAndCorrelationMiddleware)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request, _exc: RequestValidationError
) -> JSONResponse:
    return error_response(request.state.correlation_id, 400)


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


@app.get("/health")
async def health(request: Request) -> dict[str, str]:
    return correlated({"status": "ok"}, request)


@app.post("/api/diagnostics/ping")
async def diagnostics_ping(payload: PingRequest, request: Request) -> dict[str, str]:
    return correlated({"status": "accepted", "target": payload.target}, request)


@app.post("/api/search")
async def search(payload: SearchRequest, request: Request) -> dict[str, str]:
    return correlated(
        {"status": "ok", "query": payload.query, "results": "[]"}, request
    )


@app.post("/api/analyze")
async def analyze(payload: AnalyzeRequest, request: Request) -> dict[str, str]:
    return correlated({"status": "received", "text": payload.text}, request)
