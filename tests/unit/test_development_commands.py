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
    "security-exceptions",
    "container-check",
    "sbom",
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


def test_security_gates_use_pinned_scanners_and_fail_closed() -> None:
    makefile = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "semgrep==1.136.0" in makefile
    assert "--config p/python --config .semgrep.yml --error" in makefile
    assert "pip-audit==2.9.0" in makefile
    assert "$(GITLEAKS) dir" in makefile
    assert "$(TRIVY) fs" in makefile
    assert "$(TRIVY) image" in makefile
    assert "--severity HIGH,CRITICAL" in makefile
    assert "--ignore-unfixed" in makefile
    assert "scan_exit=$$?" in makefile
    assert "test $$scan_exit -eq 1" in makefile
    assert "test $$scan_exit -eq 42" in makefile


def test_security_fixtures_and_exception_schema_are_repository_contracts() -> None:
    assert (PROJECT_ROOT / "tests/security/fixtures/semgrep-unsafe.py").is_file()
    assert (PROJECT_ROOT / "tests/security/fixtures/secret-unsafe.txt").is_file()
    assert (
        PROJECT_ROOT / "tests/security/fixtures/container-policy-unsafe/Dockerfile"
    ).is_file()

    exception_policy = (
        PROJECT_ROOT / "docs/security/security-exception.yaml"
    ).read_text(encoding="utf-8")
    for required_field in (
        "finding_id:",
        "secops_owner:",
        "justification:",
        "scope:",
        "compensating_control:",
        "expires_on:",
        "follow_up:",
    ):
        assert required_field in exception_policy


def test_ci_runs_canonical_targets_and_pins_security_tools() -> None:
    workflow = (PROJECT_ROOT / ".github/workflows/quality.yml").read_text(
        encoding="utf-8"
    )

    assert "make format-check" in workflow
    assert "make lint" in workflow
    assert "make typecheck" in workflow
    assert "make test" in workflow
    assert "make sast sca secrets" in workflow
    assert "make container-check" in workflow
    assert "make quality" not in workflow
    assert "gitleaks_8.24.2_linux_x64.tar.gz" in workflow
    assert "trivy_0.74.0_Linux-64bit.tar.gz" in workflow
    assert "curl --fail" in workflow
    assert "semgrep==1.136.0" in (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")


def test_format_check_is_a_canonical_read_only_command() -> None:
    assert MAKE is not None
    result = subprocess.run(  # noqa: S603
        [MAKE, "-qp", "format-check"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode in (0, 1)
    assert "format-check:" in result.stdout


def test_ci_exposes_independent_required_quality_jobs() -> None:
    workflow = (PROJECT_ROOT / ".github/workflows/quality.yml").read_text(
        encoding="utf-8"
    )

    assert "format:" in workflow
    assert "lint:" in workflow
    assert "typecheck:" in workflow
    assert "test:" in workflow
    assert "security:" in workflow
    assert "container:" in workflow
    assert "make format-check" in workflow
    assert "make quality" not in workflow


def test_ci_jobs_use_explicit_minimum_permissions_and_stable_names() -> None:
    workflow = (PROJECT_ROOT / ".github/workflows/quality.yml").read_text(
        encoding="utf-8"
    )

    assert "permissions:\n  contents: read" in workflow
    assert "name: Format" in workflow
    assert "name: Lint" in workflow
    assert "name: Type check" in workflow
    assert "name: Tests" in workflow
    assert "name: Security" in workflow
    assert "name: Smoke container" in workflow
    assert "timeout-minutes:" in workflow
    assert "cancel-in-progress: true" in workflow
    assert "needs: [format, lint, typecheck, test, security]" in workflow
    assert "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in workflow
    assert (
        "uses: astral-sh/setup-uv@d4b2f3b6ecc6e67c4457f6d3e41ec42d3d0fcb86" in workflow
    )
    assert (
        "uses: actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38"
        in workflow
    )


def test_smoke_sbom_is_generated_from_the_built_image_and_attested_to_source() -> None:
    makefile = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "$(TRIVY) image --format cyclonedx" in makefile
    assert "$(SMOKE_IMAGE)" in makefile
    assert "org.ai-sentinel.commit" in makefile
    assert "org.ai-sentinel.lock-sha256" in makefile
    assert "components" in makefile
    assert "AI-Sentinel smoke" in makefile


def test_ci_uploads_auditable_reports_even_when_checks_fail() -> None:
    workflow = (PROJECT_ROOT / ".github/workflows/quality.yml").read_text(
        encoding="utf-8"
    )

    assert "actions/upload-artifact@" in workflow
    assert "if: always()" in workflow
    assert "retention-days: 14" in workflow
    assert "coverage.xml" in workflow
    assert "semgrep.sarif" in workflow
    assert "trivy-fs.json" in workflow
    assert "sbom.cdx.json" in workflow
    assert "github.sha" in workflow


def test_local_ci_reports_are_ignored_build_artifacts() -> None:
    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")

    assert ".artifacts/" in gitignore


def test_security_exception_check_rejects_expired_exception(tmp_path: Path) -> None:
    exception = tmp_path / "expired.yaml"
    exception.write_text(
        """finding_id: \"SEC-0001\"\n"
        "secops_owner: \"secops@example.invalid\"\n"
        "justification: \"Temporary exception\"\n"
        "scope: \"smoke image\"\n"
        "compensating_control: \"Daily review\"\n"
        "expires_on: \"2020-01-01\"\n"
        "follow_up: \"Fix before expiry\"\n""",
        encoding="utf-8",
    )

    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(PROJECT_ROOT / "scripts/check_security_exceptions.py"),
            str(exception),
            "--today",
            "2026-09-25",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "expired" in result.stderr.lower()


def test_security_exception_gate_is_part_of_quality() -> None:
    makefile = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "security-exceptions:" in makefile
    assert "$(MAKE) security-exceptions" in makefile
