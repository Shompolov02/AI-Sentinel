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
ASKPASS = PROJECT_ROOT / "tests/integration/fixtures/ssh_askpass"
NO_TELNET = PROJECT_ROOT / "tests/integration/fixtures/cowrie-no-telnet.yml"


@dataclass(frozen=True)
class Runtime:
    command: tuple[str, ...]
    environment: dict[str, str]
    base_url: str
    ssh_port: int
    telnet_port: int

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

    ports: list[int] = []
    for _ in range(3):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            ports.append(sock.getsockname()[1])
    http_port, ssh_port, telnet_port = ports

    project = f"aisentinel25-{uuid.uuid4().hex[:8]}"
    environment = {
        **os.environ,
        "BIND_ADDRESS": "127.0.0.1",
        "HTTP_PORT": str(http_port),
        "COWRIE_SSH_PORT": str(ssh_port),
        "COWRIE_TELNET_PORT": str(telnet_port),
    }
    environment["SERVER_NAME"] = "sentinel.test"
    command = (docker, "compose", "-p", project, "-f", str(COMPOSE_FILE))
    instance = Runtime(
        command, environment, f"http://127.0.0.1:{http_port}", ssh_port, telnet_port
    )
    try:
        config = instance.compose("config", "--quiet")
        assert config.returncode == 0, config.stderr
        build_flag = (
            "--no-build"
            if os.environ.get("AI_SENTINEL_RUNTIME_REUSE_IMAGES") == "1"
            else "--build"
        )
        started = instance.compose("up", "-d", build_flag, "--wait", timeout=360)
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

    reachable_tcp = runtime.compose(
        "exec", "-T", "nginx", "nc", "-z", "-w", "2", "target-app", "8000"
    )
    assert reachable_tcp.returncode == 0, reachable_tcp.stderr

    dns = runtime.compose("exec", "-T", "nginx", "nslookup", "cowrie")
    assert dns.returncode == 1, dns.stdout + dns.stderr
    route = runtime.compose(
        "exec", "-T", "nginx", "nc", "-z", "-w", "2", cowrie_ip, "2222"
    )
    assert route.returncode == 1, route.stderr


def _cowrie_events(runtime: Runtime) -> list[dict[str, object]]:
    result = runtime.compose(
        "exec",
        "-T",
        "cowrie",
        "/cowrie/cowrie-env/bin/python3",
        "-c",
        "from pathlib import Path; "
        "p=Path('var/log/cowrie/cowrie.json'); "
        "print(p.read_text() if p.exists() else '')",
    )
    assert result.returncode == 0, result.stderr
    return [json.loads(line) for line in result.stdout.splitlines() if line]


def _recv_until(conn: socket.socket, expected: bytes) -> bytes:
    data = b""
    deadline = time.monotonic() + 3
    while expected not in data.lower() and time.monotonic() < deadline:
        try:
            chunk = conn.recv(1024)
        except TimeoutError:
            break
        if not chunk:
            break
        data += chunk
    return data


@pytest.mark.runtime
def test_cowrie_health_does_not_create_fake_sessions(runtime: Runtime) -> None:
    events = _cowrie_events(runtime)
    assert not any(event.get("eventid") == "cowrie.session.connect" for event in events)


@pytest.mark.runtime
def test_cowrie_accepts_loopback_ssh_telnet_and_records_synthetic_logins(
    runtime: Runtime,
) -> None:
    ssh = shutil.which("ssh")
    assert ssh is not None
    ssh_result = subprocess.run(  # noqa: S603
        [
            ssh,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            "ConnectTimeout=3",
            "-o",
            "LogLevel=ERROR",
            "-p",
            str(runtime.ssh_port),
            "synthetic-ssh@127.0.0.1",
            "exit",
        ],
        cwd=PROJECT_ROOT,
        env={
            **runtime.environment,
            "SSH_ASKPASS": str(ASKPASS),
            "SSH_ASKPASS_REQUIRE": "force",
            "DISPLAY": ":0",
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=12,
    )
    assert ssh_result.returncode in (0, 255), ssh_result.stderr

    with socket.create_connection(("127.0.0.1", runtime.telnet_port), 3) as conn:
        conn.settimeout(3)
        assert b"login:" in _recv_until(conn, b"login:").lower()
        conn.sendall(b"synthetic-telnet\r\n")
        assert b"password:" in _recv_until(conn, b"password:").lower()
        conn.sendall(b"lab-only-password\r\n")

    for _ in range(20):
        events = _cowrie_events(runtime)
        logins = [
            event
            for event in events
            if event.get("eventid") in ("cowrie.login.failed", "cowrie.login.success")
        ]
        names = {event.get("username") for event in logins}
        if {"synthetic-ssh", "synthetic-telnet"} <= names:
            break
        time.sleep(0.2)
    assert {"synthetic-ssh", "synthetic-telnet"} <= names
    assert all(event.get("password") == "lab-only-password" for event in logins)
    ingress = runtime.compose("ps", "-q", "cowrie-ingress")
    assert ingress.returncode == 0 and ingress.stdout.strip()
    inspected = subprocess.run(  # noqa: S603
        [runtime.command[0], "inspect", ingress.stdout.strip()],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    networks = json.loads(inspected.stdout)[0]["NetworkSettings"]["Networks"]
    ingress_honeynet_ip = next(
        network["IPAddress"]
        for name, network in networks.items()
        if name.endswith("_honeynet")
    )
    assert ingress_honeynet_ip
    assert all(event.get("src_ip") != ingress_honeynet_ip for event in logins)


@pytest.mark.runtime
def test_cowrie_hardening_and_named_volumes_survive_recreation(
    runtime: Runtime,
) -> None:
    container = runtime.compose("ps", "-q", "cowrie")
    assert container.returncode == 0 and container.stdout.strip()
    docker = runtime.command[0]
    inspect = subprocess.run(  # noqa: S603
        [docker, "inspect", container.stdout.strip()],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    details = json.loads(inspect.stdout)[0]
    assert details["Config"]["User"] == "999:999"
    assert details["HostConfig"]["ReadonlyRootfs"] is True
    assert details["HostConfig"]["Privileged"] is False
    assert details["HostConfig"]["CapDrop"] == ["ALL"]
    assert details["State"]["Health"]["Status"] == "healthy"
    mounts = details["Mounts"]
    assert all(mount["Name"].startswith("aisentinel25-") for mount in mounts)
    assert {mount["Destination"] for mount in mounts} == {
        "/cowrie/cowrie-git/etc",
        "/cowrie/cowrie-git/var/log/cowrie",
        "/cowrie/cowrie-git/var/lib/cowrie",
        "/cowrie/cowrie-git/var/lib/cowrie/downloads",
    }
    before = _cowrie_events(runtime)
    assert before
    marker = runtime.compose(
        "exec",
        "-T",
        "cowrie",
        "/cowrie/cowrie-env/bin/python3",
        "-c",
        "from pathlib import Path; "
        "Path('var/lib/cowrie/downloads/synthetic-marker').write_text('lab-only')",
    )
    assert marker.returncode == 0, marker.stderr

    recreated = runtime.compose(
        "up", "-d", "--no-deps", "--force-recreate", "--wait", "cowrie", timeout=90
    )
    assert recreated.returncode == 0, recreated.stdout + recreated.stderr
    after = _cowrie_events(runtime)
    assert before[0] in after
    assert any(event.get("username") == "synthetic-ssh" for event in after)
    stored = runtime.compose(
        "exec",
        "-T",
        "cowrie",
        "/cowrie/cowrie-env/bin/python3",
        "-c",
        "from pathlib import Path; "
        "print(Path('var/lib/cowrie/downloads/synthetic-marker').read_text())",
    )
    assert stored.returncode == 0 and stored.stdout.strip() == "lab-only"


@pytest.mark.runtime
def test_cowrie_health_turns_unhealthy_without_telnet() -> None:
    docker = shutil.which("docker")
    assert docker is not None
    project = f"aisentinel25-negative-{uuid.uuid4().hex[:8]}"
    command = (
        docker,
        "compose",
        "-p",
        project,
        "-f",
        str(COMPOSE_FILE),
        "-f",
        str(NO_TELNET),
    )
    negative = Runtime(command, {**os.environ, "BIND_ADDRESS": "127.0.0.1"}, "", 0, 0)
    try:
        started = negative.compose("up", "-d", "--no-deps", "cowrie", timeout=90)
        assert started.returncode == 0, started.stdout + started.stderr
        container = negative.compose("ps", "-q", "cowrie")
        assert container.returncode == 0 and container.stdout.strip()
        for _ in range(30):
            inspected = subprocess.run(  # noqa: S603
                [
                    docker,
                    "inspect",
                    "--format",
                    "{{.State.Health.Status}}",
                    container.stdout.strip(),
                ],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                check=True,
            )
            if inspected.stdout.strip() == "unhealthy":
                break
            time.sleep(0.5)
        assert inspected.stdout.strip() == "unhealthy"
    finally:
        stopped = negative.compose("down", "--volumes", "--remove-orphans", timeout=90)
        assert stopped.returncode == 0, stopped.stdout + stopped.stderr


@pytest.mark.runtime
def test_cowrie_has_no_route_to_prod_host_or_external_network(runtime: Runtime) -> None:
    docker = runtime.command[0]
    addresses: list[str] = []
    for service in ("nginx", "target-app"):
        container = runtime.compose("ps", "-q", service)
        assert container.returncode == 0 and container.stdout.strip()
        inspected = subprocess.run(  # noqa: S603
            [
                docker,
                "inspect",
                "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                container.stdout.strip(),
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        addresses.append(inspected.stdout.strip())
    assert all(addresses)

    http_port = int(runtime.base_url.rsplit(":", 1)[1])
    targets = json.dumps(
        [
            [addresses[0], 8080],
            [addresses[1], 8000],
            ["host.docker.internal", http_port],
            ["1.1.1.1", 443],
        ]
    )
    script = (
        "import json,socket\n"
        f"targets=json.loads({targets!r})\n"
        "out=[]\n"
        "for name in ('nginx','target-app'):\n"
        " try:\n  socket.gethostbyname(name); out.append(True)\n"
        " except socket.gaierror:\n  out.append(False)\n"
        "for host,port in targets:\n"
        " try:\n  socket.create_connection((host,port),2).close(); out.append(True)\n"
        " except OSError:\n  out.append(False)\n"
        "print(json.dumps(out))"
    )
    result = runtime.compose(
        "exec",
        "-T",
        "cowrie",
        "/cowrie/cowrie-env/bin/python3",
        "-c",
        script,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [False] * 6
