from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import cast

import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "services/core"))

from fastapi.testclient import TestClient  # noqa: E402
from test_core import AUTH, configured  # noqa: E402

from ai_sentinel_core.app import create_app  # noqa: E402
from ai_sentinel_core.delivery import create_delivery_app  # noqa: E402
from ai_sentinel_core.telemetry import Journal  # noqa: E402

CONNECT = {
    "eventid": "cowrie.session.connect",
    "timestamp": "2026-10-21T10:00:00Z",
    "session": "session-1",
    "src_ip": "192.0.2.10",
    "src_port": 41000,
    "dst_port": 2222,
    "protocol": "ssh",
}
LOGIN = {
    "eventid": "cowrie.login.failed",
    "timestamp": "2026-10-21T10:00:01Z",
    "session": "session-1",
    "username": "synthetic",
    "password": "synthetic-private-password",
}


def test_login_is_normalized_with_connect_provenance_without_password(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    raw = logs / "cowrie.json"
    raw.write_text(json.dumps(CONNECT) + "\n" + json.dumps(LOGIN) + "\n")
    journal = Journal(tmp_path / "collector.db", "cowrie-lab")
    journal.scan(logs)
    event = journal.pending()[0]
    assert event["source_ip"] == "192.0.2.10"
    assert event["source_port"] == 41000
    assert event["destination_port"] == 2222
    assert event["protocol"] == "ssh"
    assert event["occurred_at"] == "2026-10-21T10:00:01Z"
    assert event["login"] == {
        "username": "synthetic",
        "outcome": "failure",
        "password_length": 26,
    }
    assert event["raw_record_ref"].startswith("cowrie:cowrie-lab:")
    assert LOGIN["password"] not in json.dumps(event)
    assert LOGIN["password"].encode() not in (tmp_path / "collector.db").read_bytes()


def test_restart_rotation_and_replay_keep_one_core_task(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    raw = logs / "cowrie.json"
    raw.write_text(json.dumps(CONNECT) + "\n" + json.dumps(LOGIN) + "\n")
    database = tmp_path / "collector.db"
    journal = Journal(database, "cowrie-lab")
    journal.scan(logs)
    original = journal.pending()[0]
    raw.rename(logs / "cowrie.json.2026-10-21")
    journal = Journal(database, "cowrie-lab")
    journal.scan(logs)
    assert journal.pending() == [original]
    with TestClient(create_app(configured(tmp_path))) as client:
        task_id = client.post("/internal/events", json=original, headers=AUTH).json()[
            "task_id"
        ]
        again = client.post("/internal/events", json=journal.pending()[0], headers=AUTH)
        assert again.json()["task_id"] == task_id
        journal.acknowledge(original["event_id"], task_id)
    assert Journal(database, "cowrie-lab").pending() == []
    with (logs / "cowrie.json.2026-10-21").open("a") as stream:
        stream.write(json.dumps(LOGIN) + "\n")
    journal.scan(logs)
    assert len(journal.pending()) == 1
    assert journal.pending()[0]["event_id"] != original["event_id"]


def test_damaged_and_unattributable_records_stay_in_local_quarantine(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    raw = logs / "cowrie.json"
    raw.write_text(
        '{"password":"synthetic-private-password",broken}\n' + json.dumps(LOGIN) + "\n"
    )
    journal = Journal(tmp_path / "collector.db", "cowrie-lab")
    journal.scan(logs)
    assert journal.pending() == []
    quarantine = journal.status()["quarantine"]
    assert len(quarantine) == 2
    assert all(item["reason"] == "invalid_record" for item in quarantine)
    assert LOGIN["password"] not in json.dumps(journal.status())
    assert LOGIN["password"].encode() not in journal.database.read_bytes()
    assert "record_quarantined" in caplog.text
    assert LOGIN["password"] not in caplog.text


def test_successful_login_creates_task_without_misleading_low(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    success = {**LOGIN, "eventid": "cowrie.login.success"}
    (logs / "cowrie.json").write_text(
        json.dumps(CONNECT) + "\n" + json.dumps(success) + "\n"
    )
    journal = Journal(tmp_path / "collector.db", "cowrie-lab")
    journal.scan(logs)
    event = journal.pending()[0]
    assert event["login"]["outcome"] == "success"
    with TestClient(create_app(configured(tmp_path))) as client:
        response = client.post("/internal/events", json=event, headers=AUTH)
        assert response.status_code == 202
        task_id = response.json()["task_id"]
        client.post("/login", json={"password": "synthetic-test-password"})
        for _ in range(100):
            task = client.get(f"/api/tasks/{task_id}").json()
            if task["state"] == "failed":
                break
            time.sleep(0.01)
        assert task["state"] == "failed"
        assert task["verdict"] is None
        assert (
            task["audit"][-1]["details"]["reason"] == "login_success_policy_pending_47"
        )


def test_fluent_bit_batch_is_acknowledged_only_after_core_acceptance(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "cowrie.json").write_text(
        json.dumps(CONNECT) + "\n" + json.dumps(LOGIN) + "\n"
    )
    journal = Journal(tmp_path / "collector.db", "cowrie-lab")
    journal.scan(logs)
    events = journal.pending()
    with TestClient(create_app(configured(tmp_path))) as core:

        def send(event: dict[str, object]) -> dict[str, str]:
            response = core.post("/internal/events", json=event, headers=AUTH)
            response.raise_for_status()
            return cast(dict[str, str], response.json())

        with TestClient(create_delivery_app(journal, send)) as delivery:
            first = delivery.post("/deliver", json=events)
            assert first.status_code == 200
            assert journal.pending() == []
            again = delivery.post("/deliver", json=events).json()
            assert (
                again["receipts"][0]["task_id"]
                == first.json()["receipts"][0]["task_id"]
            )


def test_invalid_session_shape_is_quarantined_without_stopping_collection(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    invalid = {**LOGIN, "session": {"unexpected": "object"}}
    (logs / "cowrie.json").write_text(
        "\n".join(json.dumps(r) for r in (CONNECT, invalid, LOGIN)) + "\n"
    )
    journal = Journal(tmp_path / "collector.db", "cowrie-lab")
    journal.scan(logs)
    assert len(journal.pending()) == 1
    assert len(journal.status()["quarantine"]) == 1


def test_delivery_outage_preserves_exact_event_for_retry(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "cowrie.json").write_text(
        json.dumps(CONNECT) + "\n" + json.dumps(LOGIN) + "\n"
    )
    journal = Journal(tmp_path / "collector.db", "cowrie-lab")
    journal.scan(logs)
    events = journal.pending()

    def unavailable(event: dict[str, object]) -> dict[str, str]:
        raise OSError("Synthetic unavailable transport")

    with TestClient(create_delivery_app(journal, unavailable)) as delivery:
        assert delivery.post("/deliver", json=events).status_code == 503
    assert Journal(journal.database, "cowrie-lab").pending() == events


def test_deeply_nested_json_is_quarantined_and_next_login_survives(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "cowrie.json").write_text(
        json.dumps(CONNECT)
        + "\n"
        + "[" * 5000
        + "]" * 5000
        + "\n"
        + json.dumps(LOGIN)
        + "\n"
    )
    journal = Journal(tmp_path / "collector.db", "cowrie-lab")
    journal.scan(logs)
    assert len(journal.pending()) == 1
    assert len(journal.status()["quarantine"]) == 1


def test_unfinished_oversize_line_waits_then_quarantines_without_losing_next_login(
    tmp_path: Path,
) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    raw = logs / "cowrie.json"
    raw.write_text(json.dumps(CONNECT) + "\n" + "x" * 70000)
    journal = Journal(tmp_path / "collector.db", "cowrie-lab")
    journal.scan(logs)
    assert journal.status()["quarantine"] == []
    with raw.open("a") as stream:
        stream.write("\n" + json.dumps(LOGIN) + "\n")
    journal.scan(logs)
    assert len(journal.pending()) == 1
    assert journal.status()["quarantine"][0]["length"] == 70001
