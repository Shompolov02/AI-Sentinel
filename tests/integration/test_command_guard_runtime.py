"""Optional real-ML HTTP seam; the container has no external network at all."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from core_fixtures import TEST_VERIFIER  # noqa: E402


@pytest.mark.runtime
@pytest.mark.guard
def test_real_local_guard_returns_high_through_http_without_external_network(
    tmp_path: Path,
) -> None:
    model = os.environ.get("CORE_GUARD_MODEL_DIR")
    if not model:
        if os.environ.get("AI_SENTINEL_REQUIRE_GUARD") == "1":
            pytest.fail("CORE_GUARD_MODEL_DIR is required")
        pytest.skip(
            "Real Guard requires local pinned weights; use make test-command-runtime"
        )
    docker = shutil.which("docker")
    assert docker is not None
    secrets = tmp_path / "credentials"
    secrets.mkdir()
    (secrets / "password-hash").write_text(TEST_VERIFIER)
    (secrets / "collector-tokens").write_text("synthetic-collector-token-for-tests\n")
    data = tmp_path / "data"
    data.mkdir(mode=0o777)
    data.chmod(0o777)
    name = "ai48-guard-" + uuid4().hex[:8]

    def run(*args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [docker, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    try:
        started = run(
            "run",
            "--rm",
            "-d",
            "--name",
            name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--cpus",
            "2",
            "--memory",
            "3g",
            "--pids-limit",
            "128",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=32m",  # noqa: S108
            "-v",
            f"{Path(model).resolve()}:/opt/prompt-guard:ro",
            "-v",
            f"{secrets}:/run/secrets:ro",
            "-v",
            f"{data}:/data",
            "-v",
            f"{ROOT / 'tests'}:/probe:ro",
            "-e",
            "CORE_DB_PATH=/data/core.db",
            "-e",
            "CORE_TOKENS_FILE=/run/secrets/collector-tokens",
            "-e",
            "CORE_PASSWORD_HASH_FILE=/run/secrets/password-hash",
            "-e",
            "CORE_GUARD_MODEL_DIR=/opt/prompt-guard",
            "ai-sentinel-core-guard:local",
        )
        assert started.returncode == 0, started.stderr
        probe = run(
            "exec",
            name,
            "python",
            "/probe/integration/fixtures/guard_http_probe.py",
            timeout=300,
        )
        assert probe.returncode == 0, (
            probe.stdout + probe.stderr + run("logs", name).stdout
        )
        assert "offline_guard_http_verified" in probe.stdout
        assert "offline_no_match_and_replay_verified" in probe.stdout
        restarted = run("restart", "--time", "10", name)
        assert restarted.returncode == 0, restarted.stderr
        restored = run(
            "exec",
            name,
            "python",
            "/probe/integration/fixtures/guard_http_probe.py",
            "--after-restart",
        )
        assert restored.returncode == 0, (
            restored.stdout + restored.stderr + run("logs", name).stdout
        )
        assert "offline_results_and_replay_after_restart_verified" in restored.stdout
    finally:
        run("stop", "--time", "5", name)
