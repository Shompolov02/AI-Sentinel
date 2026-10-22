"""Real TLS collector -> durable task -> authenticated read-only HTTP page."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import httpx
import pytest

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from core_fixtures import EVENT, TEST_VERIFIER  # noqa: E402


@pytest.mark.runtime
@pytest.mark.parametrize("with_collector", [False, True], ids=["synthetic", "cowrie"])
def test_core_tls_to_page_persists_on_volume_and_keeps_cowrie_isolated(
    tmp_path: Path,
    with_collector: bool,
) -> None:
    docker = shutil.which("docker")
    assert docker is not None, "Docker is required"
    secret_dir = tmp_path / "credentials"
    secret_dir.mkdir(mode=0o700)
    tls = subprocess.run(  # noqa: S603
        [shutil.which("sh") or "/bin/sh", "scripts/core_tls.sh", str(secret_dir)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert tls.returncode == 0, tls.stderr
    (secret_dir / "password-hash").write_text(TEST_VERIFIER)
    (secret_dir / "collector-tokens").write_text(
        "synthetic-collector-token-for-tests\n"
    )
    ports = []
    with ExitStack() as reservations:
        for _ in range(4):
            sock = reservations.enter_context(socket.socket())
            sock.bind(("127.0.0.1", 0))
            ports.append(sock.getsockname()[1])
    port, http_port, ssh_port, telnet_port = ports
    project = "aisentinel45-" + uuid4().hex[:8]
    environment = {
        **os.environ,
        "CORE_SECRETS_DIR": str(secret_dir),
        "CORE_BIND_ADDRESS": "127.0.0.1",
        "CORE_HTTP_PORT": str(port),
        "BIND_ADDRESS": "127.0.0.1",
        "HTTP_PORT": str(http_port),
        "COWRIE_SSH_PORT": str(ssh_port),
        "COWRIE_TELNET_PORT": str(telnet_port),
        "SERVER_NAME": "sentinel.test",
        "COWRIE_SENSOR_ID": "cowrie-runtime",
    }
    command = [
        docker,
        "compose",
        "-p",
        project,
        "-f",
        "deploy/docker-compose.yml",
        "-f",
        "deploy/core.compose.yml",
    ]

    if with_collector:
        command.extend(["-f", "deploy/collector.compose.yml"])

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

    def collect(
        event: dict[str, Any], authorized: bool = True, verify: bool = True
    ) -> dict[str, Any]:
        # The probe is a synthetic collector in core_ingest only. The CA is verified
        # by default; the negative trust test deliberately omits this private CA.
        script = """import json, ssl, sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
context = ssl.create_default_context(cafile='/ca.crt' if sys.argv[3] == '1' else None)
request = Request('https://core-intake:8443/internal/events',
    data=sys.argv[1].encode(), headers={'Content-Type':'application/json'})
if sys.argv[2] == '1':
    request.add_header('Authorization',
        'Bearer synthetic-collector-token-for-tests')
try:
    with urlopen(request, context=context, timeout=5) as response:
        print(json.dumps({'status':response.status,'body':json.load(response)}))
except HTTPError as error:
    print(json.dumps({'status':error.code}))
except URLError:
    print(json.dumps({'status':'tls_rejected'}))
"""
        result = subprocess.run(  # noqa: S603
            [
                docker,
                "run",
                "--rm",
                "--network",
                project + "_core_ingest",
                "--mount",
                f"type=bind,source={secret_dir / 'ca.crt'},target=/ca.crt,readonly",
                "--entrypoint",
                "python",
                "ai-sentinel-core:local",
                "-c",
                script,
                json.dumps(event),
                "1" if authorized else "0",
                "1" if verify else "0",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return cast(dict[str, Any], json.loads(result.stdout))

    try:
        config = compose("config", "--format", "json")
        assert config.returncode == 0, config.stderr
        model = json.loads(config.stdout)
        assert set(model["services"]["cowrie"]["networks"]) == {"honeynet"}
        for service in ("core", "core-intake"):
            assert not model["services"][service].get("ports")
        start = compose(
            "up",
            "-d",
            "--no-build"
            if os.environ.get("AI_SENTINEL_RUNTIME_REUSE_IMAGES") == "1"
            else "--build",
            "--wait",
            timeout=360,
        )
        assert start.returncode == 0, start.stdout + start.stderr
        status = compose("ps", "--format", "json")
        assert status.returncode == 0, status.stderr
        services = [json.loads(line) for line in status.stdout.splitlines() if line]
        assert len(services) == (9 if with_collector else 8), (
            "Core runbook must start the full combined stand"
        )
        assert all(service["Health"] == "healthy" for service in services)
        assert collect(EVENT, authorized=False)["status"] == 401
        assert collect(EVENT, verify=False)["status"] == "tls_rejected"
        accepted = collect(EVENT)
        assert accepted["status"] == 202
        task_id = accepted["body"]["task_id"]
        url = f"http://127.0.0.1:{port}"
        with httpx.Client(base_url=url, timeout=10) as client:
            assert client.get("/tasks").status_code == 401
            assert client.post("/internal/events", json=EVENT).status_code == 404
            assert (
                client.post(
                    "/login", json={"password": "synthetic-test-password"}
                ).status_code
                == 200
            )
            deadline = time.monotonic() + 10
            while True:
                task = client.get(f"/api/tasks/{task_id}").json()
                if task["state"] == "completed" or time.monotonic() >= deadline:
                    break
                time.sleep(0.1)
            assert task["state"] == "completed"
            assert task["history"] == ["queued", "processing", "completed"]
            assert task["verdict"]["severity"] == "Low"
            page = client.get(f"/tasks/{task_id}")
            assert "Low" in page.text and task_id in page.text
            assert page.headers["cache-control"] == "no-store"
            assert client.post(f"/tasks/{task_id}", json={}).status_code == 405
            # Recreate rather than restart: only the named volume can retain data.
            recreated = compose(
                "up", "-d", "--force-recreate", "--wait", "core", timeout=90
            )
            assert recreated.returncode == 0, recreated.stderr
            assert client.get(f"/api/tasks/{task_id}").json() == task
            assert collect(EVENT)["body"]["task_id"] == task_id
        if with_collector:
            _verify_collection(compose, ssh_port, telnet_port, url)
        for host, target_port in (
            ("core", 8000),
            ("core-intake", 8443),
            ("core-page", 8082),
            *(([("collector", 8090)]) if with_collector else []),
        ):
            identifier = compose("ps", "-q", host)
            inspected = subprocess.run(  # noqa: S603
                [docker, "inspect", identifier.stdout.strip()],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            assert inspected.returncode == 0, inspected.stderr
            addresses = [host] + [
                n["IPAddress"]
                for n in json.loads(inspected.stdout)[0]["NetworkSettings"][
                    "Networks"
                ].values()
            ]
            for address in addresses:
                for source, python in (
                    ("cowrie", "/cowrie/cowrie-env/bin/python3"),
                    ("target-app", "python"),
                ):
                    probe = compose(
                        "exec",
                        "-T",
                        source,
                        python,
                        "-c",
                        "import socket,sys\ntry:\n"
                        " socket.create_connection((sys.argv[1],int(sys.argv[2])),2)\n"
                        "except OSError:\n print('isolated')\nelse:\n"
                        " raise SystemExit('unexpected reachability')",
                        address,
                        str(target_port),
                    )
                    assert probe.returncode == 0 and "isolated" in probe.stdout, (
                        probe.stderr
                    )
    finally:
        diagnostics = compose("logs", "--tail", "30")
        print(diagnostics.stdout, file=sys.stderr)
        cleaned = compose("down", "--volumes", "--remove-orphans", timeout=90)
        assert cleaned.returncode == 0, cleaned.stderr


@pytest.mark.runtime
def test_fluent_bit_persists_coalesced_records_with_stdin_open(tmp_path: Path) -> None:
    docker = shutil.which("docker")
    assert docker is not None
    if os.environ.get("AI_SENTINEL_RUNTIME_REUSE_IMAGES") != "1":
        build = subprocess.run(  # noqa: S603
            [
                docker,
                "build",
                "-f",
                "services/collector/Dockerfile",
                "-t",
                "ai-sentinel-collector:local",
                ".",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=360,
            check=False,
        )
        assert build.returncode == 0, build.stderr
    data = tmp_path / "data"
    data.mkdir()
    second = {**EVENT, "event_id": "459f9082-ab59-472e-8d1a-b97fc788627e"}
    payload = json.dumps(EVENT) + "\n" + json.dumps(second) + "\n"
    name = "ai46-stdin-" + uuid4().hex[:8]
    probe = ROOT / "tests/integration/fixtures/fluent_bit_stdin_probe.py"
    try:
        result = subprocess.run(  # noqa: S603
            [
                docker,
                "run",
                "--rm",
                "-i",
                "--name",
                name,
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "-v",
                f"{data}:/data",
                "-v",
                f"{ROOT / 'services/collector'}:/etc/collector:ro",
                "-v",
                f"{probe}:/probe.py:ro",
                "--entrypoint",
                "python",
                "ai-sentinel-collector:local",
                "/probe.py",
            ],
            input=payload,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "Both records persisted with stdin open" in result.stdout
    finally:
        subprocess.run(  # noqa: S603
            [docker, "rm", "-f", name],
            capture_output=True,
            check=False,
            timeout=30,
        )


def _verify_collection(
    compose: Any,
    ssh_port: int,
    telnet_port: int,
    url: str,
) -> None:
    # Pause delivery to inspect real filesystem chunks, then recreate the
    # collector: only its durable journal can recover the first received_at.
    assert compose("stop", "core-intake").returncode == 0
    ssh = shutil.which("ssh")
    assert ssh is not None
    result = subprocess.run(  # noqa: S603
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
            "AI_SENTINEL_TEST_PASSWORD": "honeypot-never-copied-password",
            "DISPLAY": ":0",
        },
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode in (0, 255), result.stderr
    with socket.create_connection(("127.0.0.1", telnet_port), 3) as conn:
        conn.settimeout(3)

        def receive(expected: bytes) -> None:
            data = b""
            while expected not in data.lower():
                chunk = conn.recv(1024)
                assert chunk, data
                data += chunk

        receive(b"login:")
        conn.sendall(b"synthetic-telnet\r\n")
        receive(b"password:")
        conn.sendall(b"lab-only-password\r\n")
        time.sleep(0.2)
    damaged = compose(
        "exec",
        "-T",
        "cowrie",
        "/cowrie/cowrie-env/bin/python3",
        "-c",
        "from pathlib import Path; p=Path('var/log/cowrie/cowrie.json'); "
        "p.open('a').write('{bad-json-password:lab-only-password}\\n')",
    )
    assert damaged.returncode == 0, damaged.stderr

    def journal(expression: str) -> Any:
        result = compose(
            "exec",
            "-T",
            "collector",
            "python",
            "-c",
            "import json; from pathlib import Path; "
            "from ai_sentinel_core.telemetry import Journal; "
            "j=Journal(Path('/data/collector.db'),'cowrie-runtime'); "
            "print(json.dumps(" + expression + "))",
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        pending = journal("j.pending()")
        if len(pending) >= 2 and journal("j.status()['quarantine']"):
            break
        time.sleep(1)
    assert {e["protocol"] for e in pending} == {"ssh", "telnet"}
    assert {e["login"]["outcome"] for e in pending} == {"failure", "success"}
    assert journal("j.status()['quarantine']")
    # Forbid raw passwords in every durable collector file, including chunks
    # and SQLite journals; the only allowed copy is Cowrie's own raw log.
    clean = compose(
        "exec",
        "-T",
        "collector",
        "python",
        "-c",
        "import time; from pathlib import Path; deadline=time.monotonic()+30\n"
        "while True:\n"
        " files=[p for p in Path('/data').rglob('*') if p.is_file()]\n"
        " if any(p.suffix=='.flb' for p in files):\n  break\n"
        " assert time.monotonic()<deadline, 'No filesystem chunk observed within 30s'\n"
        " time.sleep(0.1)\n"
        "assert all(secret not in p.read_bytes() for p in files "
        "for secret in (b'lab-only-password',b'honeypot-never-copied-password'))",
    )
    assert clean.returncode == 0, clean.stderr
    recreated = compose(
        "up", "-d", "--no-deps", "--force-recreate", "--wait", "collector", timeout=90
    )
    assert recreated.returncode == 0, recreated.stderr
    assert journal("j.pending()") == pending
    assert compose("start", "core-intake").returncode == 0
    deadline = time.monotonic() + 45
    while journal("j.pending()") and time.monotonic() < deadline:
        time.sleep(1)
    assert journal("j.pending()") == []
    deliveries = journal("j.status()['deliveries']")
    assert len(deliveries) == 2
    sources = compose(
        "exec",
        "-T",
        "cowrie",
        "/cowrie/cowrie-env/bin/python3",
        "-c",
        "import json; from pathlib import Path; result={}\n"
        "for line in Path('var/log/cowrie/cowrie.json').read_text().splitlines():\n"
        " try:\n  record=json.loads(line)\n except ValueError:\n  continue\n"
        " if record.get('eventid')=='cowrie.session.connect':\n"
        "  result[record['session']]={k:record[k] for k in "
        "('src_ip','src_port','dst_port','protocol')}\n"
        "print(json.dumps(result))",
    )
    assert sources.returncode == 0, sources.stderr
    source_connections = json.loads(sources.stdout)
    with httpx.Client(base_url=url, timeout=10, trust_env=False) as client:
        assert (
            client.post(
                "/login", json={"password": "synthetic-test-password"}
            ).status_code
            == 200
        )
        for receipt in deliveries:
            task_id = receipt["task_id"]
            deadline = time.monotonic() + 10
            while True:
                task = client.get(f"/api/tasks/{task_id}").json()
                if (
                    task["state"] in ("completed", "failed")
                    or time.monotonic() >= deadline
                ):
                    break
                time.sleep(0.1)
            if task["event"]["login"]["outcome"] == "failure":
                assert task["state"] == "completed", task
                assert task["verdict"]["severity"] == "Low"
                assert "Low" in client.get(f"/tasks/{task_id}").text
            else:
                assert task["state"] == "completed", task
                assert task["verdict"]["severity"] == "High"
                assert "High" in client.get(f"/tasks/{task_id}").text
            original = source_connections[task["event"]["session_id"]]
            assert task["event"]["source_ip"] == original["src_ip"]
            assert task["event"]["source_port"] == original["src_port"]
            assert task["event"]["destination_port"] == original["dst_port"]
            assert task["event"]["protocol"] == original["protocol"]
            # Real event replay through Fluent Bit's output boundary.
            replay = compose(
                "exec",
                "-T",
                "collector",
                "python",
                "-c",
                "from urllib.request import Request,urlopen; "
                "r=Request('http://127.0.0.1:8090/deliver',data="
                + repr(json.dumps([task["event"]]).encode())
                + ",headers={'Content-Type':'application/json'}); "
                "print(urlopen(r).status)",
            )
            assert replay.returncode == 0, replay.stderr
            assert client.get(f"/api/tasks/{task_id}").json() == task
    # Controlled Cowrie timestamps through the actual read-only input, Fluent
    # Bit, verified TLS, worker and authenticated page. No wall-clock sleeps
    # simulate the five-minute policy; sleeps below only await async delivery.
    records = []
    expected = {}
    base = datetime(2026, 10, 22, 10, tzinfo=timezone.utc)
    for number, (second, level) in enumerate(
        (
            (0, "Low"),
            (60, "Low"),
            (120, "Low"),
            (180, "Low"),
            (300, "Medium"),
            (700, "Low"),
            (701, "High"),
        )
    ):
        session = f"rules-47-{number}"
        expected[session] = level
        stamp = (base + timedelta(seconds=second)).isoformat()
        records.extend(
            [
                {
                    "eventid": "cowrie.session.connect",
                    "timestamp": stamp,
                    "session": session,
                    "src_ip": "198.51.100.47",
                    "src_port": 41000,
                    "dst_port": 2222 if number % 2 == 0 else 2223,
                    "protocol": "ssh" if number % 2 == 0 else "telnet",
                },
                {
                    "eventid": "cowrie.login.success"
                    if level == "High"
                    else "cowrie.login.failed",
                    "timestamp": stamp,
                    "session": session,
                    "username": "synthetic-rules",
                    "password": "lab-only-password",
                },
            ]
        )
    payload = "".join(json.dumps(record) + "\n" for record in records)
    appended = compose(
        "exec",
        "-T",
        "cowrie",
        "/cowrie/cowrie-env/bin/python3",
        "-c",
        "from pathlib import Path; "
        "p=Path('var/log/cowrie/cowrie.json'); p.open('a').write("
        + repr(payload)
        + ")",
    )
    assert appended.returncode == 0, appended.stderr
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        all_deliveries = journal("j.status()['deliveries']")
        if len(all_deliveries) == 9:
            break
        time.sleep(1)
    assert len(all_deliveries) == 9
    with httpx.Client(base_url=url, timeout=10, trust_env=False) as client:
        assert (
            client.post(
                "/login", json={"password": "synthetic-test-password"}
            ).status_code
            == 200
        )
        observed = {}
        for receipt in all_deliveries:
            task_id = receipt["task_id"]
            deadline = time.monotonic() + 10
            while True:
                task = client.get(f"/api/tasks/{task_id}").json()
                if task["state"] == "completed" or time.monotonic() >= deadline:
                    break
                time.sleep(0.1)
            session = task["event"]["session_id"]
            if session not in expected:
                continue
            assert task["state"] == "completed", task
            assert task["verdict"]["severity"] == expected[session]
            assert expected[session] in client.get(f"/tasks/{task_id}").text
            observed[session] = task
        assert set(observed) == set(expected)
        fifth = observed["rules-47-4"]
        assert fifth["evidence"][0]["facts"]["failure_count"] == 5
        for original_task in observed.values():
            assert (
                client.get(f"/api/tasks/{original_task['task_id']}").json()
                == original_task
            )
    readonly = compose(
        "exec",
        "-T",
        "collector",
        "python",
        "-c",
        "from pathlib import Path\ntry:\n "
        "Path('/cowrie-logs/forbidden').write_text('x')\n"
        "except OSError:\n print('read_only')\nelse:\n "
        "raise SystemExit('Writable raw logs')",
    )
    assert readonly.returncode == 0 and "read_only" in readonly.stdout
