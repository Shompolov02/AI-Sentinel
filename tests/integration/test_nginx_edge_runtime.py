from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

PROJECT_ROOT = Path(__file__).parents[2]
COMPOSE_FILE = PROJECT_ROOT / "deploy/docker-compose.yml"
ASKPASS = PROJECT_ROOT / "tests/integration/fixtures/ssh_askpass"
NO_TELNET = PROJECT_ROOT / "tests/integration/fixtures/cowrie-no-telnet.yml"
PROBE_SCRIPT = """
import json, signal, socket, sys, time

def deadline(_signum, _frame):
    raise TimeoutError('probe deadline exceeded')

mode, address, port = sys.argv[1:4]
signal.signal(signal.SIGALRM, deadline)
started = time.monotonic()
signal.setitimer(signal.ITIMER_REAL, 1.8)
try:
    if mode == 'dns':
        socket.getaddrinfo(address, None, family=socket.AF_INET)
    else:
        socket.create_connection((address, int(port)), timeout=1.8).close()
    result = 'reachable'
except socket.gaierror as error:
    result = 'dns_error:' + str(error.errno)
except TimeoutError:
    result = 'timeout'
except OSError as error:
    result = 'os_error:' + str(error.errno)
finally:
    signal.setitimer(signal.ITIMER_REAL, 0)
print(json.dumps({'result': result, 'elapsed': time.monotonic() - started}))
"""


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

    def docker(self, *args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [self.command[0], *args],
            cwd=PROJECT_ROOT,
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )


def _service_inspect(runtime: Runtime, service: str) -> dict[str, Any]:
    container = runtime.compose("ps", "-q", service)
    assert container.returncode == 0 and container.stdout.strip(), (
        f"{service}: missing container: {container.stderr}"
    )
    inspected = runtime.docker("inspect", container.stdout.strip())
    assert inspected.returncode == 0, f"{service}: {inspected.stderr}"
    return cast(dict[str, Any], json.loads(inspected.stdout)[0])


def _failure_diagnostics(runtime: Runtime) -> str:
    status = runtime.compose("ps", "--all")
    logs = runtime.compose("logs", "--tail", "100")
    return (
        f"Compose status:\n{status.stdout}{status.stderr}\n"
        f"Logs:\n{logs.stdout}{logs.stderr}"
    )


def _network_address(runtime: Runtime, service: str, network: str) -> tuple[str, str]:
    details = _service_inspect(runtime, service)
    networks = details["NetworkSettings"]["Networks"]
    matches = [
        value for name, value in networks.items() if name.endswith("_" + network)
    ]
    assert len(matches) == 1, f"{service}: expected one {network} attachment"
    attachment = matches[0]
    address = attachment["IPAddress"]
    cidr = ipaddress.ip_network(f"{address}/{attachment['IPPrefixLen']}", strict=False)
    assert address and isinstance(cidr, ipaddress.IPv4Network)
    return address, str(cidr)


def _container_python(service: str) -> str:
    return "/cowrie/cowrie-env/bin/python3" if service == "cowrie" else "python"


def _network_probe(
    runtime: Runtime,
    service: str,
    direction: str,
    mode: str,
    address: str,
    port: int = 0,
) -> None:
    result = runtime.compose(
        "exec",
        "-T",
        service,
        _container_python(service),
        "-c",
        PROBE_SCRIPT,
        mode,
        address,
        str(port),
        timeout=5,
    )
    assert result.returncode == 0, (
        f"{direction}: {mode} {address}:{port}: probe failed: "
        f"{result.stdout}{result.stderr}"
    )
    outcome = json.loads(result.stdout)
    assert outcome["elapsed"] <= 2, (
        f"{direction}: {mode} {address}:{port} exceeded 2 s: {outcome}"
    )
    expected = (
        outcome["result"].startswith("dns_error:")
        if mode == "dns"
        else outcome["result"] in {"timeout", "os_error:101", "os_error:113"}
    )
    assert expected, (
        f"{direction}: unexpectedly reached {mode} {address}:{port}: {outcome}"
    )


def _container_routes(runtime: Runtime, service: str) -> list[ipaddress.IPv4Network]:
    script = "from pathlib import Path; print(Path('/proc/net/route').read_text())"
    result = runtime.compose(
        "exec", "-T", service, _container_python(service), "-c", script
    )
    assert result.returncode == 0, f"{service}: cannot read routes: {result.stderr}"
    routes = []
    for line in result.stdout.splitlines()[1:]:
        fields = line.split()
        if not fields:
            continue
        destination = int.from_bytes(bytes.fromhex(fields[1]), "little")
        mask = int.from_bytes(bytes.fromhex(fields[7]), "little")
        routes.append(ipaddress.IPv4Network((destination & mask, mask.bit_count())))
    return routes


@pytest.fixture(scope="module")
def runtime(request: pytest.FixtureRequest) -> Iterator[Runtime]:
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
    compose_plugin = subprocess.run(  # noqa: S603
        [docker, "compose", "version"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert compose_plugin.returncode == 0, (
        f"Docker Compose plugin is required: {compose_plugin.stderr}"
    )

    ports: list[int] = []
    for _ in range(3):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            ports.append(sock.getsockname()[1])
    http_port, ssh_port, telnet_port = ports

    project = f"aisentinel27-{uuid.uuid4().hex[:8]}"
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
        assert started.returncode == 0, (
            started.stdout + started.stderr + "\n" + _failure_diagnostics(instance)
        )
        for service in (
            "http-ingress",
            "nginx",
            "target-app",
            "cowrie-ingress",
            "cowrie",
        ):
            details = _service_inspect(instance, service)
            health = details["State"]["Health"]["Status"]
            assert health == "healthy", (
                f"{service}: expected healthy, got {health}\n"
                + _failure_diagnostics(instance)
            )
        failed_before = request.session.testsfailed
        yield instance
    finally:
        if request.session.testsfailed > locals().get("failed_before", 0):
            print(_failure_diagnostics(instance), file=sys.stderr)
        stopped = instance.compose("down", "--volumes", "--remove-orphans", timeout=120)
        assert stopped.returncode == 0, (
            "Compose cleanup failed:\n"
            + stopped.stdout
            + stopped.stderr
            + "\n"
            + _failure_diagnostics(instance)
        )


@pytest.mark.runtime
def test_all_services_are_healthy_and_only_ingress_has_host_ports(
    runtime: Runtime,
) -> None:
    expected = {
        "http-ingress": {"8080/tcp"},
        "cowrie-ingress": {"2222/tcp", "2223/tcp"},
        "nginx": set(),
        "target-app": set(),
        "cowrie": set(),
    }
    for service, expected_ports in expected.items():
        details = _service_inspect(runtime, service)
        assert details["State"]["Health"]["Status"] == "healthy", service
        bindings = details["HostConfig"]["PortBindings"] or {}
        assert set(bindings) == expected_ports, f"{service}: {bindings}"
        for port_bindings in bindings.values():
            assert all(binding["HostIp"] == "127.0.0.1" for binding in port_bindings)


@pytest.mark.runtime
def test_honeynet_cannot_resolve_or_reach_http_zone(runtime: Runtime) -> None:
    nginx_ip, prod_cidr = _network_address(runtime, "nginx", "prod_net")
    target_ip, _ = _network_address(runtime, "target-app", "prod_net")
    direction = "honeynet -> prod_net"
    for name in ("nginx", "target-app"):
        _network_probe(runtime, "cowrie", direction, "dns", name)
    for address, port in ((nginx_ip, 8080), (target_ip, 8000)):
        _network_probe(runtime, "cowrie", direction, "tcp", address, port)
    forbidden = ipaddress.IPv4Network(prod_cidr)
    assert not any(
        route.overlaps(forbidden) for route in _container_routes(runtime, "cowrie")
    ), f"{direction}: route to forbidden subnet {prod_cidr}"


@pytest.mark.runtime
def test_target_app_cannot_resolve_or_reach_honeynet(runtime: Runtime) -> None:
    cowrie_ip, honeynet_cidr = _network_address(runtime, "cowrie", "honeynet")
    ingress_ip, _ = _network_address(runtime, "cowrie-ingress", "honeynet")
    direction = "prod_net -> honeynet"
    for name in ("cowrie", "cowrie-ingress"):
        _network_probe(runtime, "target-app", direction, "dns", name)
    for address, port in (
        (cowrie_ip, 2222),
        (cowrie_ip, 2223),
        (ingress_ip, 2222),
        (ingress_ip, 2223),
    ):
        _network_probe(runtime, "target-app", direction, "tcp", address, port)
    forbidden = ipaddress.IPv4Network(honeynet_cidr)
    assert not any(
        route.overlaps(forbidden) for route in _container_routes(runtime, "target-app")
    ), f"{direction}: route to forbidden subnet {honeynet_cidr}"


@pytest.mark.runtime
def test_vulnerable_workloads_have_no_host_or_external_route(runtime: Runtime) -> None:
    inspected = runtime.docker("network", "inspect", "bridge")
    assert inspected.returncode == 0, inspected.stderr
    host_gateway = json.loads(inspected.stdout)[0]["IPAM"]["Config"][0]["Gateway"]
    assert host_gateway
    for service in ("target-app", "cowrie"):
        direction = f"{service} -> host/external"
        routes = _container_routes(runtime, service)
        assert all(route.prefixlen > 0 for route in routes), (
            f"{direction}: unexpected default route {routes}"
        )
        _network_probe(runtime, service, direction, "tcp", host_gateway, 80)
        _network_probe(runtime, service, direction, "tcp", "198.51.100.1", 443)


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
def test_edge_accepts_body_below_two_mib_and_rejects_larger_body(
    runtime: Runtime,
) -> None:
    payload = b'{"text":"synthetic"}'
    with httpx.Client(base_url=runtime.base_url, timeout=10, trust_env=False) as client:
        accepted = client.post(
            "/api/analyze",
            content=payload + b" " * (1_500_000 - len(payload)),
            headers={"Content-Type": "application/json"},
        )
        rejected = client.post(
            "/api/analyze",
            content=payload + b" " * (2 * 1024 * 1024 + 1 - len(payload)),
            headers={"Content-Type": "application/json"},
        )

    assert accepted.status_code == 200
    assert accepted.json()["status"] == "RECEIVED"
    assert rejected.status_code == 413


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
    ingress_backend_ip, _ = _network_address(runtime, "http-ingress", "http_edge")
    assert matches[-1]["remote_addr"] not in (spoofed_ip, ingress_backend_ip)
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
    assert app_matches[-1]["client_ip"] == matches[-1]["remote_addr"]


@pytest.mark.runtime
def test_http_logs_and_sqlite_survive_service_recreation(runtime: Runtime) -> None:
    marker = f"runtime-persist-{uuid.uuid4().hex[:8]}"
    row_id = 1_000_000 + int(uuid.uuid4().hex[:6], 16)
    with httpx.Client(base_url=runtime.base_url, timeout=5, trust_env=False) as client:
        assert client.post("/api/search", json={"query": "srv-web"}).status_code == 200
        response = client.get(f"/health?marker={marker}")
        assert response.status_code == 200

    insert = runtime.compose(
        "exec",
        "-T",
        "target-app",
        "python",
        "-c",
        "import sqlite3,sys; from target_app.surfaces import asset_db_path; "
        "db=sqlite3.connect(asset_db_path()); "
        "db.execute('INSERT INTO assets VALUES (?,?,?,?,?)', "
        "(int(sys.argv[1]),sys.argv[2],'10.0.0.99','active','Synthetic marker')); "
        "db.commit(); db.close()",
        str(row_id),
        marker,
    )
    assert insert.returncode == 0, insert.stderr
    before = runtime.compose("exec", "-T", "nginx", "cat", "/var/log/nginx/access.log")
    assert before.returncode == 0 and marker in before.stdout, before.stderr

    recreated = runtime.compose(
        "up",
        "-d",
        "--force-recreate",
        "--wait",
        "target-app",
        "nginx",
        "http-ingress",
        timeout=180,
    )
    assert recreated.returncode == 0, recreated.stdout + recreated.stderr
    after = runtime.compose("exec", "-T", "nginx", "cat", "/var/log/nginx/access.log")
    assert after.returncode == 0 and marker in after.stdout, after.stderr
    with httpx.Client(base_url=runtime.base_url, timeout=5, trust_env=False) as client:
        search = client.post("/api/search", json={"query": marker})
    assert search.status_code == 200
    assert any(row["hostname"] == marker for row in search.json()["results"])


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


def _record_telnet_login(runtime: Runtime, username: str) -> None:
    with socket.create_connection(("127.0.0.1", runtime.telnet_port), 3) as conn:
        conn.settimeout(3)
        assert b"login:" in _recv_until(conn, b"login:").lower()
        conn.sendall(username.encode() + b"\r\n")
        assert b"password:" in _recv_until(conn, b"password:").lower()
        conn.sendall(b"lab-only-password\r\n")


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

    _record_telnet_login(runtime, "synthetic-telnet")

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
    assert all(mount["Name"].startswith("aisentinel27-") for mount in mounts)
    assert {mount["Destination"] for mount in mounts} == {
        "/cowrie/cowrie-git/etc",
        "/cowrie/cowrie-git/var/log/cowrie",
        "/cowrie/cowrie-git/var/lib/cowrie",
        "/cowrie/cowrie-git/var/lib/cowrie/downloads",
    }
    marker_name = f"persist-{uuid.uuid4().hex[:8]}"
    _record_telnet_login(runtime, marker_name)
    for _ in range(20):
        before = _cowrie_events(runtime)
        if any(event.get("username") == marker_name for event in before):
            break
        time.sleep(0.2)
    assert any(event.get("username") == marker_name for event in before)
    marker = runtime.compose(
        "exec",
        "-T",
        "cowrie",
        "/cowrie/cowrie-env/bin/python3",
        "-c",
        "from pathlib import Path; "
        f"Path('var/lib/cowrie/downloads/{marker_name}').write_text('lab-only')",
    )
    assert marker.returncode == 0, marker.stderr

    recreated = runtime.compose(
        "up", "-d", "--no-deps", "--force-recreate", "--wait", "cowrie", timeout=90
    )
    assert recreated.returncode == 0, recreated.stdout + recreated.stderr
    after = _cowrie_events(runtime)
    assert any(event.get("username") == marker_name for event in after)
    stored = runtime.compose(
        "exec",
        "-T",
        "cowrie",
        "/cowrie/cowrie-env/bin/python3",
        "-c",
        "from pathlib import Path; "
        f"print(Path('var/lib/cowrie/downloads/{marker_name}').read_text())",
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
