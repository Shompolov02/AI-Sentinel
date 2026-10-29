"""AC1 through the launched collector, real Fluent Bit, files and local logs."""

import os
import shutil
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest

ROOT = Path(__file__).parents[2]


@pytest.fixture(scope="module")
def collector_image() -> str:
    docker = shutil.which("docker")
    assert docker is not None
    image = os.environ.get(
        "AI_SENTINEL_PRESSURE_IMAGE", "ai-sentinel-collector:issue52"
    )
    if os.environ.get("AI_SENTINEL_RUNTIME_REUSE_IMAGES") != "1":
        built = subprocess.run(  # noqa: S603
            [docker, "build", "-f", "services/collector/Dockerfile", "-t", image, "."],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=360,
            check=False,
        )
        assert built.returncode == 0, built.stderr
    return image


@pytest.mark.runtime
@pytest.mark.parametrize(
    "scenario", ["pressure", "boundaries", "expiry", "expiry_fault", "expiry_logfault"]
)
def test_collector_stops_at_budget_and_resumes_without_lost_events(
    scenario: str,
    collector_image: str,
) -> None:
    docker = shutil.which("docker")
    assert docker is not None
    kind = "expiry" if scenario.startswith("expiry") else scenario
    probe = ROOT / f"tests/integration/fixtures/buffer_{kind}_probe.py"
    name = "ai52-pressure-" + uuid4().hex[:8]
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
                "--security-opt",
                "no-new-privileges:true",
                "--tmpfs",
                "/data:rw,size=32m,uid=10001,gid=10001,mode=0700",
                "--tmpfs",
                "/cowrie-logs:rw,size=8m,uid=10001,gid=10001,mode=0700",
                "--tmpfs",
                "/tmp:rw,size=16m",  # noqa: S108 - isolated container tmpfs
                "-e",
                "COWRIE_SENSOR_ID=pressure-test",
                "-e",
                "PYTHONPATH=/app",
                "-e",
                "COLLECTOR_OUTBOX_BYTES=10000",
                "-e",
                "COLLECTOR_CHUNK_BYTES=4194304",
                "-v",
                f"{probe}:/probe.py:ro",
                "-v",
                f"{ROOT / 'services/core/ai_sentinel_core'}:/app/ai_sentinel_core:ro",
                "--entrypoint",
                "python",
                collector_image,
                "/probe.py",
                scenario,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=100,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        expected = {
            "pressure": "all 40 unique records delivered",
            "boundaries": "Core 80/100/60 hysteresis, disk reserve and chunks verified",
            "expiry": "3 local critical losses, 6 fresh tasks",
        }
        assert expected[kind] in result.stdout
        assert "collector_backpressure" in result.stderr
        assert "collector_intake_stopped" in result.stderr
        assert "collector_intake_resumed" in result.stderr
        assert "marker-" not in result.stderr
    finally:
        subprocess.run(  # noqa: S603
            [docker, "rm", "-f", name],
            capture_output=True,
            timeout=20,
            check=False,
        )
