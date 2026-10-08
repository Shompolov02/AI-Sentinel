"""Intentionally vulnerable, bounded laboratory surfaces for Target App."""

from __future__ import annotations

import os
import selectors
import signal
import sqlite3
import subprocess
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SEED_ASSETS = (
    (1, "srv-web-01", "10.0.0.10", "active", "Synthetic web server"),
    (2, "srv-database-01", "10.0.0.15", "active", "Synthetic database server"),
    (3, "srv-backup-01", "10.0.0.20", "maintenance", "Synthetic backup server"),
    (4, "workstation-01", "10.0.0.30", "active", "Synthetic workstation"),
)
COMMAND_TIMEOUT_SECONDS = 5.0
MAX_COMMAND_OUTPUT_BYTES = 4096


@dataclass(frozen=True)
class PingOutput:
    stdout: str
    stderr: str
    exit_code: int
    truncated: bool


class PingTimedOut(Exception):
    """The laboratory command exceeded its fixed deadline."""


def asset_db_path() -> Path:
    configured = os.environ.get("TARGET_APP_DB_PATH")
    return Path(configured) if configured else BASE_DIR / "data" / "assets.db"


def search_assets(query: str) -> list[dict[str, str | int]]:
    """Search synthetic assets; SQL interpolation is intentional for issue #23."""
    path = asset_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            "CREATE TABLE IF NOT EXISTS assets ("
            "id INTEGER PRIMARY KEY, hostname TEXT NOT NULL, "
            "ip_address TEXT NOT NULL, status TEXT NOT NULL, "
            "description TEXT NOT NULL)"
        )
        connection.executemany(
            "INSERT OR IGNORE INTO assets "
            "(id, hostname, ip_address, status, description) VALUES (?, ?, ?, ?, ?)",
            SEED_ASSETS,
        )
        connection.commit()
        # This one query is deliberately interpolated so the documented SQLi
        # payload can be reproduced against a synthetic, single-table database.
        sql = (
            "SELECT id, hostname, ip_address, status, description "  # noqa: S608
            f"FROM assets WHERE hostname LIKE '%{query}%' LIMIT 50"
        )
        # Enforce the response cap outside SQL as well: an injected comment can
        # remove LIMIT from the deliberately vulnerable statement.
        rows = connection.execute(sql).fetchmany(50)
    return [dict(row) for row in rows]


def run_ping(target: str) -> PingOutput:
    """Run the intentionally injectable command with bounded time and output."""
    # The shell expansion is the documented lab vulnerability. The container
    # runs without extra capabilities, host mounts, or real data.
    process = subprocess.Popen(  # noqa: S602  # nosemgrep: no-shell-true-in-security-gates
        f"ping -c 2 {target}",
        shell=True,  # nosemgrep
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    captured_bytes = 0
    truncated = False
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    selector = selectors.DefaultSelector()
    try:
        if process.stdout is None or process.stderr is None:
            raise RuntimeError("Command pipes unavailable")
        selector.register(process.stdout, selectors.EVENT_READ, stdout_chunks)
        selector.register(process.stderr, selectors.EVENT_READ, stderr_chunks)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PingTimedOut
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                room = MAX_COMMAND_OUTPUT_BYTES - captured_bytes
                key.data.append(chunk[:room])
                captured_bytes += min(len(chunk), room)
                truncated |= len(chunk) > room
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PingTimedOut
        try:
            exit_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise PingTimedOut from exc
        return PingOutput(
            stdout=b"".join(stdout_chunks).decode("utf-8", errors="ignore"),
            stderr=b"".join(stderr_chunks).decode("utf-8", errors="ignore"),
            exit_code=exit_code,
            truncated=truncated,
        )
    except PingTimedOut:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    finally:
        selector.close()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
