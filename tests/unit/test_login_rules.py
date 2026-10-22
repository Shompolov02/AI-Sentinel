"""Cowrie records to visible verdicts, with controlled event and Core time."""

from __future__ import annotations

import json
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast

from fastapi.testclient import TestClient
from test_core import AUTH, configured
from test_telemetry import CONNECT, LOGIN

from ai_sentinel_core.app import create_app
from ai_sentinel_core.telemetry import Journal

BASE = datetime(2026, 10, 22, 10, tzinfo=timezone.utc)


class CowriePath:
    def __init__(self, directory: Path) -> None:
        self.logs = directory / "logs"
        self.logs.mkdir()
        self.journal = Journal(directory / "collector.db", "cowrie-rules")
        self.number = 0

    def event(
        self,
        second: float,
        *,
        protocol: str = "ssh",
        ip: str = "192.0.2.10",
        success: bool = False,
    ) -> dict[str, Any]:
        self.number += 1
        session = f"session-{self.number}"
        stamp = (BASE + timedelta(seconds=second)).isoformat()
        connect = {
            **CONNECT,
            "session": session,
            "src_ip": ip,
            "protocol": protocol,
            "timestamp": stamp,
        }
        login = {
            **LOGIN,
            "session": session,
            "timestamp": stamp,
            "eventid": "cowrie.login.success" if success else "cowrie.login.failed",
        }
        with (self.logs / "cowrie.json").open("a") as stream:
            stream.write(json.dumps(connect) + "\n" + json.dumps(login) + "\n")
        self.journal.scan(self.logs)
        return self.journal.pending()[-1]


def visible(client: TestClient, event: dict[str, Any], expected: str) -> dict[str, Any]:
    response = client.post("/internal/events", json=event, headers=AUTH)
    assert response.status_code == 202
    task_id = response.json()["task_id"]
    for _ in range(200):
        task = client.get(f"/api/tasks/{task_id}").json()
        if task["state"] in ("completed", "failed"):
            break
        time.sleep(0.01)
    assert task["state"] == "completed", task
    assert task["verdict"]["severity"] == expected
    assert expected in client.get(f"/tasks/{task_id}").text
    return cast(dict[str, Any], task)


def test_fifth_failure_counts_ssh_telnet_and_sessions_without_rewriting_history(
    tmp_path: Path,
) -> None:
    path = CowriePath(tmp_path)
    settings = replace(configured(tmp_path), clock=lambda: BASE.timestamp() + 86400)
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        originals = []
        for second, protocol, level in (
            (0, "ssh", "Low"),
            (30, "telnet", "Low"),
            (60, "ssh", "Low"),
            (90, "telnet", "Low"),
            (120, "ssh", "Medium"),
            (150, "telnet", "Medium"),
        ):
            originals.append(
                visible(client, path.event(second, protocol=protocol), level)
            )
        assert originals[4]["evidence"][0]["facts"]["failure_count"] == 5
        assert originals[5]["audit"][-2]["details"]["severity"] == "Medium"
        for task in originals:
            assert client.get(f"/api/tasks/{task['task_id']}").json() == task


def test_window_includes_exact_five_minutes_but_excludes_older_records(
    tmp_path: Path,
) -> None:
    path = CowriePath(tmp_path)
    now = [BASE.timestamp() + 100000]
    settings = replace(configured(tmp_path), clock=lambda: now[0])
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        for second in (0, 60, 120, 180):
            visible(client, path.event(second), "Low")
            now[0] += 1  # Core time is deliberately unrelated to the event window.
        exact = visible(client, path.event(300), "Medium")
        assert exact["evidence"][0]["facts"]["failure_count"] == 5
        # New IP: four old failures are all just outside its window.
        for _ in range(4):
            visible(client, path.event(0, ip="192.0.2.11"), "Low")
        outside = visible(client, path.event(300.001, ip="192.0.2.11"), "Low")
        assert outside["evidence"][0]["facts"]["failure_count"] == 1


def test_late_delivery_ignores_future_events_and_never_revisits_verdicts(
    tmp_path: Path,
) -> None:
    path = CowriePath(tmp_path)
    with TestClient(create_app(configured(tmp_path))) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        for _ in range(4):
            visible(client, path.event(100), "Low")
        future = visible(client, path.event(100), "Medium")
        late = visible(client, path.event(0), "Low")
        assert late["evidence"][0]["facts"]["failure_count"] == 1
        assert client.get(f"/api/tasks/{future['task_id']}").json() == future
        # A buffered batch with unrelated received_at must not count as a burst.
        for second in (1000, 1400, 1800, 2200, 2600):
            visible(client, path.event(second), "Low")


def test_replay_and_restart_preserve_count_and_success_does_not_reset_failures(
    tmp_path: Path,
) -> None:
    path = CowriePath(tmp_path)
    settings = configured(tmp_path)
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        first_event = path.event(0)
        first = visible(client, first_event, "Low")
        for _ in range(4):
            replay = visible(client, first_event, "Low")
            assert replay == first
        for second in (10, 20, 30):
            visible(client, path.event(second), "Low")
        success = visible(client, path.event(35, success=True), "High")
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        fifth = visible(client, path.event(40, protocol="telnet"), "Medium")
        assert fifth["evidence"][0]["facts"]["failure_count"] == 5
        assert client.get(f"/api/tasks/{first['task_id']}").json() == first
        assert client.get(f"/api/tasks/{success['task_id']}").json() == success
        visible(client, path.event(41, ip="2001:db8::1"), "Low")


def test_delayed_worker_uses_each_events_admission_snapshot(tmp_path: Path) -> None:
    path = CowriePath(tmp_path)
    settings = configured(tmp_path)
    # No lifespan: the public intake remains available with analysis stopped.
    with_worker_stopped = TestClient(create_app(settings))
    events = [path.event(second) for second in range(6)]
    ids = []
    for event in events:
        response = with_worker_stopped.post(
            "/internal/events", json=event, headers=AUTH
        )
        assert response.status_code == 202
        ids.append(response.json()["task_id"])
    with_worker_stopped.close()
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        for event, task_id, level in zip(
            events, ids, ("Low", "Low", "Low", "Low", "Medium", "Medium"), strict=True
        ):
            task = visible(client, event, level)
            assert task["task_id"] == task_id
