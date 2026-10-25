"""The page ingress supplies a safe emergency page without a running Core."""

import shutil
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from core_fixtures import TEST_VERIFIER  # noqa: E402


@pytest.mark.runtime
def test_page_ingress_shows_503_when_core_process_is_unavailable(
    tmp_path: Path,
) -> None:
    docker = shutil.which("docker")
    assert docker is not None, "Docker is required"
    name = "ai50-page-outage-" + uuid4().hex[:8]

    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [docker, *args], capture_output=True, text=True, timeout=30, check=False
        )

    try:
        network = run("network", "create", name)
        assert network.returncode == 0, network.stderr
        started = run(
            "run",
            "--rm",
            "--detach",
            "--name",
            name,
            "--network",
            name,
            "--user",
            "101",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",  # noqa: S108
            "--publish",
            "127.0.0.1::8082",
            "--entrypoint",
            "nginx",
            "--volume",
            f"{ROOT / 'deploy/core/page.conf'}:/etc/nginx/core.conf:ro",
            "ai-sentinel-nginx:local",
            "-c",
            "/etc/nginx/core.conf",
            "-g",
            "daemon off;",
        )
        assert started.returncode == 0, started.stderr
        published = run("port", name, "8082/tcp")
        assert published.returncode == 0, published.stderr
        base = "http://" + published.stdout.strip()
        with httpx.Client(base_url=base, timeout=10, trust_env=False) as client:
            deadline = time.monotonic() + 15
            while True:
                try:
                    if client.get("/health").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                assert time.monotonic() < deadline, run("logs", name).stderr
                time.sleep(0.1)
            for path in ("/tasks?q=private-marker", "/login"):
                response = client.get(path)
                assert response.status_code == 503
                assert "Core недоступен" in response.text
                assert "проверьте журналы и контейнеры" in response.text
                assert response.headers["cache-control"] == "no-store"
                assert "private-marker" not in response.text
            credentials = tmp_path / "credentials"
            credentials.mkdir()
            (credentials / "password-hash").write_text(TEST_VERIFIER)
            (credentials / "collector-tokens").write_text(
                "synthetic-collector-token-for-tests\n"
            )
            backend = run(
                "run",
                "--rm",
                "--detach",
                "--name",
                name + "-core",
                "--network",
                name,
                "--network-alias",
                "core",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=16m",  # noqa: S108
                "--tmpfs",
                "/data:rw,uid=10001,gid=10001,mode=700,size=16m",
                "--volume",
                f"{credentials}:/run/secrets:ro",
                "--volume",
                f"{ROOT / 'services/core/ai_sentinel_core'}:/app/ai_sentinel_core:ro",
                "--env",
                "CORE_DB_PATH=/data/core.db",
                "--env",
                "CORE_TOKENS_FILE=/run/secrets/collector-tokens",
                "--env",
                "CORE_PASSWORD_HASH_FILE=/run/secrets/password-hash",
                "ai-sentinel-core:local",
            )
            assert backend.returncode == 0, backend.stderr
            deadline = time.monotonic() + 20
            while client.get("/login").status_code != 200:
                assert time.monotonic() < deadline, run("logs", name + "-core").stderr
                time.sleep(0.1)
            assert (
                client.post(
                    "/login", json={"password": "synthetic-test-password"}
                ).status_code
                == 200
            )
            assert "История сигналов Core" in client.get("/tasks").text
            assert run("stop", "--time", "5", name + "-core").returncode == 0
            stopped = client.get("/tasks")
            assert stopped.status_code == 503
            assert "Core недоступен" in stopped.text
            assert "История сигналов Core" not in stopped.text
            assert client.get("/internal/events").status_code == 404
    finally:
        run("rm", "--force", name + "-core")
        run("rm", "--force", name)
        run("network", "rm", name)
