from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2] / "services/target-app"))

from fastapi.testclient import TestClient

from target_app.main import app

client = TestClient(app)


def test_health_returns_ok() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "correlation_id": response.headers["x-request-id"],
    }


def test_dashboard_contains_warning_and_interactive_forms() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert "LABORATORY ENVIRONMENT — INTENTIONALLY VULNERABLE TARGET" in response.text
    assert "Network Diagnostics" in response.text
    assert "Asset Catalog Search" in response.text
    assert "AI Security Event Intake" in response.text
    assert 'action="/api/diagnostics/ping"' in response.text
    assert 'action="/api/search"' in response.text
    assert 'action="/api/analyze"' in response.text


def test_security_headers_are_set_on_all_responses() -> None:
    for path in ("/", "/health", "/missing"):
        response = client.get(path)
        assert response.headers["content-security-policy"] == (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"
        )
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"


def test_api_response_echoes_server_correlation_id() -> None:
    response = client.post("/api/search", json={"query": "ssh"})

    assert response.status_code == 200
    assert response.headers["x-request-id"] == response.json()["correlation_id"]
    assert response.json()["query"] == "ssh"


def test_client_supplied_request_id_is_not_trusted() -> None:
    response = client.post(
        "/api/search", json={"query": "ssh"}, headers={"X-Request-ID": "attacker-value"}
    )

    assert response.headers["x-request-id"] != "attacker-value"
    assert response.json()["correlation_id"] == response.headers["x-request-id"]


def test_validation_error_uses_canonical_error_and_correlation_contract() -> None:
    response = client.post("/api/analyze", json={"text": "x" * 4097})

    assert response.status_code == 400
    assert response.json() == {
        "error": "Request could not be processed",
        "correlation_id": response.headers["x-request-id"],
        "status": 400,
    }


def test_api_routes_accept_expected_payloads_and_return_correlation_id() -> None:
    requests = (
        ("/api/diagnostics/ping", {"target": "127.0.0.1"}),
        ("/api/search", {"query": "admin"}),
        ("/api/analyze", {"text": "failed login"}),
    )

    for path, payload in requests:
        response = client.post(path, json=payload)
        assert response.status_code == 200
        assert response.json()["correlation_id"] == response.headers["x-request-id"]


def test_openapi_document_is_valid_and_lists_api_routes() -> None:
    response = client.get("/openapi.json")
    specification = response.json()

    assert response.status_code == 200
    assert specification["openapi"].startswith("3.")
    assert "/api/diagnostics/ping" in specification["paths"]
    assert "/api/search" in specification["paths"]
    assert "/api/analyze" in specification["paths"]
