"""Real TLS collector -> durable task -> authenticated read-only HTTP page."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import httpx
import pytest

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from core_fixtures import EVENT, TEST_VERIFIER  # noqa: E402


@pytest.mark.runtime
def test_core_tls_to_page_persists_on_volume_and_keeps_cowrie_isolated(
    tmp_path: Path,
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
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    project = "aisentinel45-" + uuid4().hex[:8]
    environment = {
        **os.environ,
        "CORE_SECRETS_DIR": str(secret_dir),
        "CORE_BIND_ADDRESS": "127.0.0.1",
        "CORE_HTTP_PORT": str(port),
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
            "core-page",
            "core-intake",
            "cowrie",
            timeout=360,
        )
        assert start.returncode == 0, start.stdout + start.stderr
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
        for host, target_port in (
            ("core", 8000),
            ("core-intake", 8443),
            ("core-page", 8082),
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
                probe = compose(
                    "exec",
                    "-T",
                    "cowrie",
                    "/cowrie/cowrie-env/bin/python3",
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
