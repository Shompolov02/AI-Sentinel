"""Security boundary of the normalized three-manifest collector deployment."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path


def test_collector_has_read_only_source_and_no_route_into_managing_networks(
    tmp_path: Path,
) -> None:
    docker = shutil.which("docker")
    assert docker is not None
    result = subprocess.run(  # noqa: S603
        [
            docker,
            "compose",
            "--env-file",
            os.devnull,
            "-f",
            "deploy/docker-compose.yml",
            "-f",
            "deploy/core.compose.yml",
            "-f",
            "deploy/collector.compose.yml",
            "config",
            "--format",
            "json",
        ],
        cwd=Path(__file__).parents[2],
        env={
            **os.environ,
            "CORE_SECRETS_DIR": str(tmp_path),
            "CORE_BIND_ADDRESS": "127.0.0.1",
            "COWRIE_SENSOR_ID": "policy-test",
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    services = json.loads(result.stdout)["services"]
    collector = services["collector"]
    assert set(collector["networks"]) == {"core_ingest"}
    assert set(services["cowrie"]["networks"]) == {"honeynet"}
    assert collector["read_only"] is True
    assert collector["user"] == "10001:10001"
    assert collector["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in collector["security_opt"]
    assert not collector.get("ports")
    mounts = {v["target"]: v for v in collector["volumes"]}
    assert mounts["/cowrie-logs"]["source"] == "cowrie-logs"
    assert mounts["/cowrie-logs"]["read_only"] is True
    assert mounts["/run/secrets/collector-tokens"]["read_only"] is True
    assert mounts["/run/secrets/ca.crt"]["read_only"] is True
    assert not any("docker.sock" in v["source"] for v in collector["volumes"])
