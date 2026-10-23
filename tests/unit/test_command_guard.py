"""Commands are observed through Core's public intake, API and SecOps page."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from test_core import AUTH, configured

from ai_sentinel_core.app import create_app
from core_fixtures import EVENT


def command_event(text: str = "pwd") -> dict[str, Any]:
    event = {
        **EVENT,
        "event_type": "command",
        "cowrie_event_type": "cowrie.command.input",
    }
    event.pop("login")
    event["command"] = {"text": text}
    return event


def terminal(client: TestClient, task_id: str) -> dict[str, Any]:
    for _ in range(200):
        item: dict[str, Any] = client.get(f"/api/tasks/{task_id}").json()
        if item["state"] in ("completed", "failed"):
            return item
        time.sleep(0.01)
    raise AssertionError("Task did not reach a terminal state")


def test_command_without_available_guard_has_no_invented_verdict(
    tmp_path: Path,
) -> None:
    with TestClient(create_app(configured(tmp_path))) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        accepted = client.post("/internal/events", json=command_event(), headers=AUTH)
        assert accepted.status_code == 202
        task_id = accepted.json()["task_id"]
        task = terminal(client, task_id)
        assert task["state"] == "failed"
        assert task["verdict"] is None
        assert task["analysis"]["analysis_method"] == "Fallback"
        assert task["analysis"]["guard_result"]["status"] == "error"
        assert task["analysis"]["reason_code"] == "guard_unavailable"
        assert task["analysis"]["mitre_attack"] is None
        assert task["evidence"][0]["raw_record_ref"] == EVENT["raw_record_ref"]
        page = client.get(f"/tasks/{task_id}")
        assert page.status_code == 200
        assert "Не удалось оценить" in page.text
        assert "Fallback" in page.text
        assert "не определена" in page.text


def test_cowrie_command_reaches_visible_task_without_copying_unrelated_fields(
    tmp_path: Path,
) -> None:
    import json

    from test_telemetry import CONNECT

    from ai_sentinel_core.telemetry import Journal

    logs = tmp_path / "logs"
    logs.mkdir()
    command: dict[str, Any] = {
        "eventid": "cowrie.command.input",
        "timestamp": "2026-10-23T10:00:00Z",
        "session": CONNECT["session"],
        "input": "pwd",
        "password": "synthetic-unrelated-password",
    }
    (logs / "cowrie.json").write_text(
        json.dumps(CONNECT) + "\n" + json.dumps(command) + "\n"
    )
    journal = Journal(tmp_path / "collector.db", "command-test")
    journal.scan(logs)
    assert len(journal.pending()) == 1
    event = journal.pending()[0]
    with TestClient(create_app(configured(tmp_path))) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        accepted = client.post("/internal/events", json=event, headers=AUTH)
        assert accepted.status_code == 202
        task = terminal(client, accepted.json()["task_id"])
        assert task["event"]["command"] == {"text": "pwd"}
        assert "login" not in task["event"]
        assert task["event"]["session_id"] == CONNECT["session"]
        assert task["event"]["source_ip"] == CONNECT["src_ip"]
        assert command["password"] not in json.dumps(task)
        assert "cowrie:command-test:" in client.get(f"/tasks/{task['task_id']}").text


def test_command_is_inert_on_detail_page_and_absent_from_list(tmp_path: Path) -> None:
    text = '<script>alert("synthetic-command-marker")</script>'
    with TestClient(create_app(configured(tmp_path))) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        receipt = client.post(
            "/internal/events", json=command_event(text), headers=AUTH
        ).json()
        terminal(client, receipt["task_id"])
        page = client.get(f"/tasks/{receipt['task_id']}")
        assert "&lt;script&gt;" in page.text
        assert text not in page.text
        assert page.headers["cache-control"] == "no-store"
        listing = client.get("/tasks").text
        assert "Команда Cowrie" in listing
        assert "synthetic-command-marker" not in listing
