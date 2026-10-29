"""Issue #52: actual Cowrie, bounded Fluent Bit, TLS, reader and network isolation."""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from core_fixtures import TEST_VERIFIER  # noqa: E402


@pytest.mark.runtime
def test_bounded_buffer_real_cowrie_tls_expiry_and_isolation(tmp_path: Path) -> None:
    docker, shell, ssh = (shutil.which(name) for name in ("docker", "sh", "ssh"))
    assert docker and shell and ssh
    credentials = tmp_path / "credentials"
    credentials.mkdir()
    for script in ("core_tls.sh", "raw_reader_credentials.sh"):
        generated = subprocess.run(  # noqa: S603
            [shell, str(ROOT / "scripts" / script), str(credentials)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert generated.returncode == 0, generated.stderr
    (credentials / "password-hash").write_text(TEST_VERIFIER)
    (credentials / "collector-tokens").write_text("synthetic-buffer-stack-token\n")
    clock_dir = tmp_path / "clock"
    clock_dir.mkdir(mode=0o755)
    first = float(int(time.time()))

    def advance(now: float) -> None:
        temporary = clock_dir / "next"
        temporary.write_text(str(now))
        temporary.chmod(0o644)
        temporary.replace(clock_dir / "now")

    advance(first)
    with ExitStack() as reservations:
        ports = []
        for _ in range(4):
            listener = reservations.enter_context(socket.socket())
            listener.bind(("127.0.0.1", 0))
            ports.append(listener.getsockname()[1])
    page_port, edge_port, ssh_port, telnet_port = ports
    project = "aisentinel52-" + uuid4().hex[:8]
    environment = {
        **os.environ,
        "CORE_SECRETS_DIR": str(credentials),
        "CORE_BIND_ADDRESS": "127.0.0.1",
        "CORE_HTTP_PORT": str(page_port),
        "BIND_ADDRESS": "127.0.0.1",
        "HTTP_PORT": str(edge_port),
        "COWRIE_SSH_PORT": str(ssh_port),
        "COWRIE_TELNET_PORT": str(telnet_port),
        "COWRIE_SENSOR_ID": "buffer-stack",
        "SERVER_NAME": "sentinel.test",
        "COLLECTOR_OUTBOX_BYTES": "10000",
        "COLLECTOR_CHUNK_BYTES": "4194304",
    }
    for index, key in enumerate(
        (
            "PROD_NET_SUBNET",
            "HONEYNET_SUBNET",
            "COWRIE_INGRESS_SUBNET",
            "HTTP_EDGE_SUBNET",
            "HTTP_INGRESS_SUBNET",
            "CORE_INGEST_SUBNET",
            "CORE_MANAGEMENT_SUBNET",
            "CORE_HTTP_INGRESS_SUBNET",
        ),
        1,
    ):
        environment[key] = f"172.28.{index * 10}.0/24"
    clock_fixture = ROOT / "tests/integration/fixtures/retention_clock_entrypoint.py"
    source_mount = str(ROOT / "services/core/ai_sentinel_core")
    overlay = tmp_path / "buffer-clock.json"
    clock_services = {
        service: {
            "entrypoint": ["python", "/retention_clock.py", role],
            "command": [],
            "environment": {"PYTHONPATH": "/app"},
            "volumes": [
                f"{clock_dir}:/test-clock:ro",
                f"{clock_fixture}:/retention_clock.py:ro",
                f"{source_mount}:/app/ai_sentinel_core:ro",
            ],
        }
        for service, role in [
            ("core", "core"),
            ("collector", "collector"),
            ("raw-reader", "reader"),
            ("retention", "retention"),
        ]
    }
    for service in (
        "nginx",
        "http-ingress",
        "target-app",
        "cowrie-ingress",
        "cowrie",
        "core",
        "core-intake",
        "core-page",
        "collector",
        "raw-reader",
        "retention",
    ):
        clock_services.setdefault(service, {})["healthcheck"] = {
            "interval": "1s",
            "start_period": "30s",
        }
    overlay.write_text(json.dumps({"services": clock_services}))
    command = [docker, "compose", "-p", project]
    for manifest in (
        "docker-compose.yml",
        "core.compose.yml",
        "collector.compose.yml",
        "evidence.compose.yml",
        "retention.compose.yml",
    ):
        command += ["-f", str(ROOT / "deploy" / manifest)]
    command += ["-f", str(overlay)]

    def compose(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [*command, *args],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def require(*args: str, timeout: int = 60) -> str:
        result = compose(*args, timeout=timeout)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout

    def collector(script: str, *args: str) -> str:
        return require("exec", "-T", "collector", "python", "-c", script, *args)

    def health() -> dict[str, Any]:
        return dict(
            json.loads(
                collector(
                    "from urllib.request import urlopen; "
                    "print(urlopen('http://127.0.0.1:8090/health',timeout=3).read().decode())"
                )
            )
        )

    def pending() -> list[dict[str, Any]]:
        return list(
            json.loads(
                collector(
                    "import json;from pathlib import Path;"
                    "from ai_sentinel_core.telemetry import Journal;"
                    "j=Journal(Path('/data/collector.db'),'buffer-stack',"
                    "clock=lambda:float(Path('/test-clock/now').read_text()));"
                    "print(json.dumps(j.pending()))"
                )
            )
        )

    def until(predicate: Callable[[], bool], timeout: int = 60) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.25)
        raise AssertionError("Buffer stack did not reach expected observable state")

    def receive(conn: socket.socket, expected: bytes | None = None) -> None:
        received = b""
        while True:
            chunk = conn.recv(4096)
            assert chunk, received
            received += chunk
            if (expected is not None and expected in received.lower()) or (
                expected is None and received.endswith((b"$ ", b"# "))
            ):
                return
            assert len(received) < 65536

    def telnet() -> socket.socket:
        conn = socket.create_connection(("127.0.0.1", telnet_port), 10)
        conn.settimeout(10)
        receive(conn, b"login:")
        conn.sendall(b"synthetic-buffer\r\n")
        receive(conn, b"password:")
        conn.sendall(b"lab-only-password\r\n")
        receive(conn)
        return conn

    def send(conn: socket.socket, text: str) -> None:
        conn.sendall((text + "\r\n").encode())
        receive(conn)

    def task_ids(client: httpx.Client) -> set[str]:
        page = client.get("/tasks")
        assert page.status_code == 200
        return set(re.findall(r'href="/tasks/([0-9a-f-]{36})"', page.text))

    def tasks(
        client: httpx.Client, exclude: set[str] | None = None
    ) -> list[dict[str, Any]]:
        result = []
        for task_id in task_ids(client) - (exclude or set()):
            reply = client.get(f"/api/tasks/{task_id}")
            if reply.status_code == 503:
                # The existing outage contract permits a temporary 503 during
                # source maintenance. Retry the snapshot within until's bound.
                return []
            assert reply.status_code == 200, reply.status_code
            result.append(reply.json())
        return result

    def sign_in(client: httpx.Client) -> None:
        assert (
            client.post(
                "/login", json={"password": "synthetic-test-password"}
            ).status_code
            == 200
        )

    def all_commands(
        client: httpx.Client, expected: list[str], exclude: set[str] | None = None
    ) -> bool:
        observed = {
            item["event"].get("command", {}).get("text")
            for item in tasks(client, exclude)
            if item["state"] in ("completed", "failed")
        }
        return set(expected) <= observed

    def chunks_have(marker: str) -> bool:
        return (
            collector(
                "import sys;from pathlib import Path;"
                "print(any(sys.argv[1].encode() in p.read_bytes() "
                "for p in Path('/data/chunks').rglob('*') if p.is_file()))",
                marker,
            ).strip()
            == "True"
        )

    def collector_bytes_absent(markers: list[str]) -> bool:
        # The heartbeat belongs to UID 999 and contains only a timestamp.
        # Validate it as its owner; never widen its permissions for a probe.
        require(
            "exec",
            "-T",
            "retention",
            "python",
            "-c",
            "from pathlib import Path; "
            "float(Path('/data/retention-heartbeat').read_text())",
        )
        return (
            collector(
                """import json,sys
from pathlib import Path
markers=[text.encode() for text in json.loads(sys.argv[1])]
clean=True
for path in Path('/data').rglob('*'):
    if path == Path('/data/retention-heartbeat') or not path.is_file():
        continue
    try:
        content=path.read_bytes()
    except FileNotFoundError:
        continue
    if any(marker in content for marker in markers):
        clean=False
print(clean)
""",
                json.dumps(markers),
            ).strip()
            == "True"
        )

    wave = [f"echo buffer52-recovery-{i}-" + "x" * 900 for i in range(12)]
    alive = "echo buffer52-alive-at-stop"
    old = [f"echo buffer52-expiring-{i}-" + "x" * 900 for i in range(3)]
    fresh = [f"echo buffer52-fresh-{i}-" + "x" * 500 for i in range(8)]
    try:
        require("config", "--quiet")
        options = (
            ["--no-build", "--pull", "never"]
            if os.environ.get("AI_SENTINEL_RUNTIME_REUSE_IMAGES") == "1"
            else ["--build"]
        )
        require("up", "-d", "--wait", *options, timeout=480)
        cowrie_id = require("ps", "-q", "cowrie").strip()
        # Exercise the real TLS route, service authorization and CA validation.
        tls_probe = """import json, ssl, sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
ca='/run/secrets/ca.crt' if sys.argv[1]=='ca' else None
context=ssl.create_default_context(cafile=ca)
request=Request('https://core-intake:8443/internal/events',method='HEAD')
if sys.argv[2]=='token':
    token=open('/run/secrets/collector-tokens').read().strip()
    request.add_header('Authorization','Bearer '+token)
try:
    with urlopen(request,context=context,timeout=5) as response:
        print(json.dumps({'status':response.status,'depth':response.headers['X-Core-Queue-Depth']}))
except HTTPError as error:
    print(json.dumps({'status':error.code}))
except URLError:
    print(json.dumps({'status':'tls_rejected'}))
"""
        assert json.loads(collector(tls_probe, "ca", "token")) == {
            "status": 200,
            "depth": "0",
        }
        assert json.loads(collector(tls_probe, "ca", "none"))["status"] == 401
        assert (
            json.loads(collector(tls_probe, "default", "token"))["status"]
            == "tls_rejected"
        )
        print("Verified real TLS HEAD, token rejection and CA validation", flush=True)
        with (
            httpx.Client(
                base_url=f"http://127.0.0.1:{page_port}", timeout=10, trust_env=False
            ) as client,
            telnet() as session,
        ):
            sign_in(client)
            assert client.head("/internal/events").status_code == 404
            until(
                lambda: bool(tasks(client))
            )  # Native Telnet login arrived through TLS.
            require("stop", "core-intake")
            attempted = subprocess.run(  # noqa: S603
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
                    "-p",
                    str(ssh_port),
                    "root@127.0.0.1",
                    "exit",
                ],
                env={
                    **os.environ,
                    "SSH_ASKPASS": str(ROOT / "tests/integration/fixtures/ssh_askpass"),
                    "SSH_ASKPASS_REQUIRE": "force",
                    "DISPLAY": ":0",
                    "AI_SENTINEL_TEST_PASSWORD": "honeypot-never-copied-password",
                },
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            assert attempted.returncode in (0, 255), attempted.stderr
            for text in wave:
                send(session, text)
            until(lambda: health()["intake"] == "stopped")
            assert 8000 <= health()["outbox_bytes"] <= 10000
            assert health()["chunk_bytes"] <= 4194304
            print("Verified bounded stop at 10000-byte outbox", flush=True)
            send(session, alive)
            buffered = pending()
            assert collector_bytes_absent(
                ["lab-only-password", "honeypot-never-copied-password"]
            )
            require(
                "up",
                "-d",
                "--no-deps",
                "--no-build",
                "--force-recreate",
                "--wait",
                "collector",
                timeout=120,
            )
            assert pending() == buffered
            require("start", "core-intake")
            until(lambda: all_commands(client, [*wave, alive]), timeout=120)
            until(lambda: health()["intake"] == "normal" and not pending())
            received: list[dict[str, Any]] = []

            def read_received() -> bool:
                nonlocal received
                received = tasks(client)
                return bool(received)

            until(read_received)
            baseline_ids = {item["task_id"] for item in received}
            assert len({item["event"]["event_id"] for item in received}) == len(
                received
            )
            for event in buffered:
                assert (
                    sum(
                        item["event"]["event_id"] == event["event_id"]
                        and item["event"]["received_at"] == event["received_at"]
                        for item in received
                    )
                    == 1
                )
            logins = [
                item
                for item in received
                if item["event"]["event_type"] == "login_attempt"
            ]
            assert {item["event"]["protocol"] for item in logins} == {"ssh", "telnet"}
            assert {item["verdict"]["severity"] for item in logins} == {"Low", "High"}
            print(
                "Verified SSH/Telnet recovery, stable IDs and receipt times", flush=True
            )
            require("stop", "core-intake")
            for text in old:
                send(session, text)
            until(lambda: all(chunks_have(text) for text in old))
            old_ids = {
                event["event_id"]
                for event in pending()
                if event.get("command", {}).get("text") in old
            }
            assert len(old_ids) == 3
            advance(first + 86400)
            for text in fresh:
                send(session, text)
            until(lambda: health()["intake"] == "stopped")
            advance(first + 14 * 86400 - 1)
            sign_in(client)
            assert all(chunks_have(text) for text in old)
            assert "buffer_event_expired" not in require(
                "logs", "--no-color", "collector"
            )
            before_history = (
                client.get("/tasks")
                .text.split('aria-label="История сигналов Core"')[1]
                .split("</table>")[0]
            )
            advance(first + 14 * 86400)
            until(
                lambda: (
                    require("logs", "--no-color", "collector").count(
                        "buffer_event_expired event_id="
                    )
                    == 3
                )
            )
            until(lambda: collector_bytes_absent(old))
            # No new task row exists at all while these events are undelivered;
            # this does not depend on raw-source detail availability.
            assert task_ids(client) == baseline_ids
            after_history = (
                client.get("/tasks")
                .text.split('aria-label="История сигналов Core"')[1]
                .split("</table>")[0]
            )
            assert after_history == before_history
            print(
                "Verified three expirations at day 14 without Core tasks or web alerts",
                flush=True,
            )
            advance(first + 14 * 86400 + 1)
            require("start", "core-intake")
            until(lambda: all_commands(client, fresh, baseline_ids), timeout=120)
            delivered_fresh: list[dict[str, Any]] = []

            def read_fresh() -> bool:
                nonlocal delivered_fresh
                delivered_fresh = tasks(client, baseline_ids)
                return bool(delivered_fresh)

            until(read_fresh)
            assert len(delivered_fresh) == len(fresh)
            assert not old_ids & {item["event"]["event_id"] for item in delivered_fresh}
            assert require("ps", "-q", "cowrie").strip() == cowrie_id
            send(session, "pwd")
            until(lambda: all_commands(client, ["pwd"], baseline_ids))
            print(
                "Verified fresh delivery and live Cowrie session after expiry",
                flush=True,
            )
            logs = require("logs", "--no-color", "collector")
            assert all(
                code in logs
                for code in (
                    "collector_backpressure",
                    "collector_intake_stopped",
                    "collector_intake_resumed",
                )
            )
            assert logs.count("buffer_event_expired event_id=") == 3
            assert "buffer52-expiring-" not in logs
            assert json.loads(collector(tls_probe, "ca", "token"))["status"] == 200
            # Actual DNS and direct-IP probes on the same composed stand.
            targets = [
                ("core", 8000),
                ("core-intake", 8443),
                ("collector", 8090),
                ("raw-reader", 8443),
                ("core-page", 8082),
                ("target-app", 8000),
            ]
            addresses = []
            for service, port in targets:
                inspected = subprocess.run(  # noqa: S603
                    [docker, "inspect", require("ps", "-q", service).strip()],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=10,
                )
                details = json.loads(inspected.stdout)[0]
                if service == "collector":
                    assert set(details["NetworkSettings"]["Networks"]) == {
                        project + "_core_ingest"
                    }
                    assert details["HostConfig"]["ReadonlyRootfs"]
                    assert not details["HostConfig"]["PortBindings"]
                    assert "ALL" in details["HostConfig"]["CapDrop"]
                    assert all(
                        mount["Destination"] != "/var/run/docker.sock"
                        for mount in details["Mounts"]
                    )
                    assert all(
                        not mount["RW"]
                        for mount in details["Mounts"]
                        if mount["Destination"] == "/cowrie-logs"
                    )
                addresses.append((service, port))
                addresses.extend(
                    (network["IPAddress"], port)
                    for network in details["NetworkSettings"]["Networks"].values()
                )
            isolated = require(
                "exec",
                "-T",
                "cowrie",
                "/cowrie/cowrie-env/bin/python3",
                "-c",
                """import json,socket,sys
for host,port in json.loads(sys.argv[1]):
    try:
        socket.create_connection((host,port),0.7).close()
    except OSError:
        continue
    raise AssertionError('Unexpected Cowrie reachability: '+host)
print('cowrie_dns_and_ip_isolated')
""",
                json.dumps(addresses),
            )
            assert "cowrie_dns_and_ip_isolated" in isolated
            info = subprocess.run(  # noqa: S603
                [docker, "inspect", cowrie_id],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            assert set(json.loads(info.stdout)[0]["NetworkSettings"]["Networks"]) == {
                project + "_honeynet"
            }
            print(
                "Cowrie SSH/Telnet -> bounded Fluent Bit -> TLS -> Core: "
                "recovery, expiry, isolation verified"
            )
    finally:
        diagnostics = compose("logs", "--no-color", "--tail", "80")
        (tmp_path / "buffer-stack-logs.txt").write_text(
            diagnostics.stdout + diagnostics.stderr
        )
        result = compose("down", "--volumes", "--remove-orphans", timeout=120)
        assert result.returncode == 0, result.stderr
