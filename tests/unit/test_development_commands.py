from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
MAKE = shutil.which("make")
CANONICAL_TARGETS = (
    "bootstrap",
    "format",
    "lint",
    "typecheck",
    "test",
    "sast",
    "sca",
    "secrets",
    "container-check",
    "quality",
)


def test_makefile_exposes_canonical_development_commands() -> None:
    assert MAKE is not None
    # MAKE is an absolute executable path resolved from the trusted developer PATH.
    result = subprocess.run(  # noqa: S603
        [MAKE, "-qp", "quality"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode in (0, 1)
    for target in CANONICAL_TARGETS:
        assert f"{target}:" in result.stdout


def test_quality_is_a_read_only_aggregate() -> None:
    assert MAKE is not None
    # MAKE is an absolute executable path resolved from the trusted developer PATH.
    result = subprocess.run(  # noqa: S603
        [MAKE, "-n", "quality"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert "ruff format --check" in result.stdout
    assert "ruff format ." not in result.stdout
    assert "uv lock --check" in result.stdout
