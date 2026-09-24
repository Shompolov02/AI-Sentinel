from __future__ import annotations

import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
MAKE = shutil.which("make")
RUFF = shutil.which("ruff") or str(PROJECT_ROOT / ".venv/bin/ruff")
PYTHON_MINIMUM = (3, 10)
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


def test_format_check_rejects_an_unformatted_fixture(tmp_path: Path) -> None:
    fixture = tmp_path / "unformatted.py"
    fixture.write_text(
        textwrap.dedent(
            """
            def fixture( ):
              return {"status":"ok"}
            """
        ),
        encoding="utf-8",
    )

    result = subprocess.run(  # noqa: S603
        [RUFF, "format", "--check", str(fixture)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0


def test_supported_minimum_python_version_is_enforced() -> None:
    assert sys.version_info >= PYTHON_MINIMUM
    workspace = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.10"' in workspace


def test_ci_tests_the_supported_minimum_python_version() -> None:
    workflow = (PROJECT_ROOT / ".github/workflows/quality.yml").read_text(
        encoding="utf-8"
    )
    assert 'python-version: ["3.10", "3.11"]' in workflow


def test_quality_uses_a_nonzero_coverage_gate() -> None:
    makefile = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "--cov-fail-under=80" in makefile


def test_container_check_validates_the_normalized_compose_model() -> None:
    makefile = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")
    assert (
        "docker compose -f infrastructure/compose/smoke.yaml config --quiet" in makefile
    )
