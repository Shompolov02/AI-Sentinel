from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parents[2]
DOCKER = shutil.which("docker")
DOCKERFILE = PROJECT_ROOT / "infrastructure/docker/Dockerfile"
COMPOSE_FILE = PROJECT_ROOT / "infrastructure/compose/smoke.yaml"


def _docker_daemon_is_available() -> bool:
    if DOCKER is None:
        return False
    result = subprocess.run(  # noqa: S603
        [DOCKER, "info"],
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


DOCKER_DAEMON_AVAILABLE = _docker_daemon_is_available()


def test_smoke_dockerfile_defines_a_pinned_multistage_nonroot_runtime() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    assert dockerfile.count("FROM ") >= 2
    assert "python:3.11-slim-bookworm@sha256:" in dockerfile
    assert (
        "COPY packages/smoke/src/ai_sentinel_smoke /src/ai_sentinel_smoke" in dockerfile
    )
    assert "USER 10001:10001" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert "ARG " not in dockerfile
    assert "COPY .env" not in dockerfile


def test_compose_normalized_model_has_safe_named_network() -> None:
    docker = DOCKER
    assert docker is not None
    result = subprocess.run(  # noqa: S603
        [docker, "compose", "-f", str(COMPOSE_FILE), "config", "--format", "json"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    model = json.loads(result.stdout)
    service = model["services"]["smoke"]

    assert model["networks"]["sentinel_baseline"]["name"] == "sentinel_baseline"
    assert list(service["networks"]) == ["sentinel_baseline"]
    assert service["user"] == "10001:10001"
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert "privileged" not in service
    assert "network_mode" not in service
    assert "volumes" not in service


@pytest.mark.skipif(
    not DOCKER_DAEMON_AVAILABLE,
    reason="Docker daemon is required for image smoke test",
)
def test_smoke_image_builds_and_runs_as_nonroot() -> None:
    docker = DOCKER
    assert docker is not None
    image = "ai-sentinel-smoke:test"
    build = subprocess.run(  # noqa: S603
        [docker, "build", "--file", str(DOCKERFILE), "--tag", image, "."],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert build.returncode == 0
    result = subprocess.run(  # noqa: S603
        [docker, "run", "--rm", "--read-only", image],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(result.stdout) == {
        "project": "AI-Sentinel",
        "status": "ok",
    }
