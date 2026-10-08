from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

PROJECT_ROOT = Path(__file__).parents[2]
COMPOSE_FILE = PROJECT_ROOT / "deploy/docker-compose.yml"


@dataclass(frozen=True)
class Runtime:
    command: tuple[str, ...]
    environment: dict[str, str]
    base_url: str

    def compose(
        self, *args: str, timeout: int = 30
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [*self.command, *args],
            cwd=PROJECT_ROOT,
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )


@pytest.fixture(scope="module")
def runtime() -> Iterator[Runtime]:
    docker = shutil.which("docker")
    available = (
        docker is not None
        and subprocess.run(  # noqa: S603
            [docker, "info"], capture_output=True, check=False, timeout=15
        ).returncode
        == 0
    )
    if not available:
        if os.environ.get("AI_SENTINEL_REQUIRE_DOCKER") == "1":
            pytest.fail("Docker Engine and Compose are required for runtime acceptance")
        pytest.skip("Docker Engine is unavailable")
    assert docker is not None

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    project = f"aisentinel24-{uuid.uuid4().hex[:8]}"
    environment = {**os.environ, "BIND_ADDRESS": "127.0.0.1", "HTTP_PORT": str(port)}
    environment["SERVER_NAME"] = "sentinel.test"
    command = (docker, "compose", "-p", project, "-f", str(COMPOSE_FILE))
    instance = Runtime(command, environment, f"http://127.0.0.1:{port}")
    try:
        config = instance.compose("config", "--quiet")
        assert config.returncode == 0, config.stderr
        started = instance.compose("up", "-d", "--build", "--wait", timeout=360)
        assert started.returncode == 0, started.stdout + started.stderr
        yield instance
    finally:
        stopped = instance.compose("down", "--volumes", "--remove-orphans", timeout=120)
        assert stopped.returncode == 0, stopped.stdout + stopped.stderr


@pytest.mark.runtime
def test_published_edge_routes_http_and_rejects_unknown_host(runtime: Runtime) -> None:
    with httpx.Client(base_url=runtime.base_url, timeout=5, trust_env=False) as client:
        for path in ("/", "/docs", "/redoc", "/openapi.json", "/health"):
            response = client.get(path)
            assert response.status_code == 200, path
            assert response.headers["x-request-id"]
        assert "LABORATORY ENVIRONMENT" in client.get("/").text
        assert "/api/search" in client.get("/openapi.json").json()["paths"]
        assert client.post("/api/search", json={"query": "ssh"}).status_code == 200
        missing = client.get("/missing")
        assert missing.status_code == 404
        assert missing.json()["correlation_id"] == missing.headers["x-request-id"]
        assert missing.headers["x-frame-options"] == "DENY"
        assert (
            client.get("/health", headers={"Host": "sentinel.test"}).status_code == 200
        )
        with pytest.raises(httpx.RemoteProtocolError):
            client.get("/unknown-host-probe", headers={"Host": "attacker.test"})

    app_logs = runtime.compose("logs", "--no-log-prefix", "target-app")
    assert "/unknown-host-probe" not in app_logs.stdout


@pytest.mark.runtime
def test_edge_overwrites_spoofed_headers_and_correlates_logs(runtime: Runtime) -> None:
    spoofed_ip = "203.0.113.254"
    with httpx.Client(base_url=runtime.base_url, timeout=5, trust_env=False) as client:
        response = client.get(
            "/health",
            headers={
                "X-Request-ID": "b" * 32,
                "X-Forwarded-For": spoofed_ip,
                "X-Real-IP": spoofed_ip,
                "X-Forwarded-Host": "attacker.test",
                "Forwarded": f"for={spoofed_ip};host=attacker.test",
            },
        )

    request_id = response.headers["x-request-id"]
    assert request_id != "b" * 32
    assert response.json()["correlation_id"] == request_id
    assert len(request_id) == 32
    assert response.headers["content-security-policy"].startswith("default-src 'self'")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "nginx/" not in response.headers.get("server", "")

    for _ in range(10):
        access = runtime.compose(
            "exec", "-T", "nginx", "cat", "/var/log/nginx/access.log"
        )
        assert access.returncode == 0, access.stderr
        entries = [json.loads(line) for line in access.stdout.splitlines() if line]
        matches = [entry for entry in entries if entry["request_id"] == request_id]
        if matches:
            break
        time.sleep(0.2)
    assert matches
    assert matches[-1]["status"] == 200
    assert matches[-1]["request_uri"] == "/health"
    assert matches[-1]["request_method"] == "GET"
    assert matches[-1]["http_x_forwarded_for"] == spoofed_ip
    assert matches[-1]["remote_addr"] != spoofed_ip
    assert matches[-1]["time_iso8601"]
    assert matches[-1]["request_time"] >= 0

    app_logs = runtime.compose("logs", "--no-log-prefix", "target-app")
    app_entries = [
        json.loads(line)
        for line in app_logs.stdout.splitlines()
        if line.startswith("{")
    ]
    app_matches = [
        entry for entry in app_entries if entry.get("correlation_id") == request_id
    ]
    assert app_matches
    assert app_matches[-1]["client_ip"] != spoofed_ip


@pytest.mark.runtime
def test_nginx_cannot_resolve_or_reach_cowrie(runtime: Runtime) -> None:
    cowrie = runtime.compose("ps", "-q", "cowrie")
    assert cowrie.returncode == 0 and cowrie.stdout.strip()
    inspected = subprocess.run(  # noqa: S603
        [
            runtime.command[0],
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            cowrie.stdout.strip(),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    cowrie_ip = inspected.stdout.strip()
    assert cowrie_ip

    reachable_dns = runtime.compose("exec", "-T", "nginx", "nslookup", "target-app")
    assert reachable_dns.returncode == 0, reachable_dns.stderr
    reachable_tcp = runtime.compose(
        "exec", "-T", "nginx", "nc", "-z", "-w", "2", "target-app", "8000"
    )
    assert reachable_tcp.returncode == 0, reachable_tcp.stderr

    dns = runtime.compose("exec", "-T", "nginx", "nslookup", "cowrie")
    assert dns.returncode != 0
    route = runtime.compose(
        "exec", "-T", "nginx", "nc", "-z", "-w", "2", cowrie_ip, "2222"
    )
    assert route.returncode == 1, route.stderr
