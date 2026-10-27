"""An isolated real Fluent Bit process proves live chunk erasure and replay."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest

ROOT = Path(__file__).parents[2]


def test_retention_manifest_limits_writer_authority_and_preserves_cowrie(
    tmp_path: Path,
) -> None:
    docker = shutil.which("docker")
    assert docker is not None
    command = [docker, "compose"]
    for manifest in (
        "docker-compose.yml",
        "core.compose.yml",
        "collector.compose.yml",
        "retention.compose.yml",
    ):
        command += ["-f", str(ROOT / "deploy" / manifest)]
    result = subprocess.run(  # noqa: S603
        [*command, "config", "--format", "json"],
        cwd=ROOT,
        env={
            **os.environ,
            "CORE_BIND_ADDRESS": "127.0.0.1",
            "CORE_SECRETS_DIR": str(tmp_path / "configuration-only"),
            "COWRIE_SENSOR_ID": "manifest-test",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    import json

    services = json.loads(result.stdout)["services"]
    cleaner = services["retention"]
    assert cleaner["network_mode"] == "none"
    assert cleaner["read_only"] is True
    assert cleaner["user"] == "999:999"
    assert cleaner["cap_drop"] == ["ALL"]
    assert not cleaner.get("ports")
    assert {mount["target"] for mount in cleaner["volumes"]} == {
        "/data",
        "/cowrie-logs",
        "/cowrie-tty",
        "/cowrie-downloads",
    }
    assert services["cowrie"]["command"][5] == "cowrie.python.logfile.logger"
    assert set(services["cowrie"]["networks"]) == {"honeynet"}
    assert next(
        m for m in services["collector"]["volumes"] if m["target"] == "/cowrie-logs"
    )["read_only"]


@pytest.mark.runtime
def test_running_collector_erases_old_chunks_and_replays_fresh_outbox(
    tmp_path: Path,
) -> None:
    docker = shutil.which("docker")
    assert docker is not None
    secrets = tmp_path / "credentials"
    secrets.mkdir()
    shell = shutil.which("sh")
    assert shell is not None
    tls = subprocess.run(  # noqa: S603
        [shell, "scripts/core_tls.sh", str(secrets)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert tls.returncode == 0, tls.stderr
    (secrets / "collector-tokens").write_text("synthetic-buffer-collector-token")
    data, logs = tmp_path / "data", tmp_path / "logs"
    data.mkdir()
    logs.mkdir()
    if os.environ.get("AI_SENTINEL_RUNTIME_REUSE_IMAGES") != "1":
        built = subprocess.run(  # noqa: S603
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
        assert built.returncode == 0, built.stderr
    name = "ai51-retention-" + uuid4().hex[:8]
    try:
        result = subprocess.run(  # noqa: S603
            [
                docker,
                "run",
                "--rm",
                "--name",
                name,
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "-e",
                "COWRIE_SENSOR_ID=retention-live",
                "-e",
                "PYTHONPATH=/app",
                "-v",
                f"{data}:/data",
                "-v",
                f"{logs}:/input",
                "-v",
                f"{logs}:/cowrie-logs:ro",
                "-v",
                f"{secrets}:/run/secrets:ro",
                "-v",
                f"{ROOT / 'services/core/ai_sentinel_core'}:/app/ai_sentinel_core:ro",
                "-v",
                str(ROOT / "tests/integration/fixtures/retention_buffer_probe.py")
                + ":/probe.py:ro",
                "--entrypoint",
                "python",
                "ai-sentinel-collector:local",
                "/probe.py",
            ],
            capture_output=True,
            text=True,
            timeout=75,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "Live chunks erased; fresh outbox replayed" in result.stdout
        assert "Gzip and plain source cleaned while collector runs" in result.stdout
    finally:
        subprocess.run(  # noqa: S603
            [docker, "rm", "-f", name],
            capture_output=True,
            timeout=20,
            check=False,
        )
