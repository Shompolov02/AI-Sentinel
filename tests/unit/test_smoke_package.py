from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from ai_sentinel_smoke import smoke_status


def test_smoke_status_reports_project_readiness() -> None:
    assert smoke_status() == {
        "project": "AI-Sentinel",
        "status": "ok",
    }


def test_installed_smoke_command_runs_outside_repository_root(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "ai_sentinel_smoke"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(result.stdout) == {
        "project": "AI-Sentinel",
        "status": "ok",
    }
