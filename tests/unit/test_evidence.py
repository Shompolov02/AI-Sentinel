"""Evidence is observed through authenticated Core HTTP and the reader HTTP API."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from email.message import Message
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.error import HTTPError

import pytest
from fastapi.testclient import TestClient
from test_command_guard import command_event, terminal
from test_core import AUTH, configured
from test_telemetry import CONNECT

from ai_sentinel_core.app import create_app
from ai_sentinel_core.raw_source import ReaderSettings, create_reader_app
from ai_sentinel_core.telemetry import Journal


def test_operator_opens_exact_raw_record_inside_its_card(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    command = '<script>alert("evidence-marker")</script>' + "x" * 520
    raw = (
        json.dumps(
            {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-10-24T10:00:00Z",
                "session": CONNECT["session"],
                "input": command,
                "extra": "raw-only-marker",
            }
        )
        + "\n"
    )
    (logs / "cowrie.json").write_text(json.dumps(CONNECT) + "\n" + raw)
    database = tmp_path / "collector.db"
    journal = Journal(database, "evidence-test")
    journal.scan(logs)
    event = journal.pending()[0]
    token = tmp_path / "reader-token"
    token.write_text("synthetic-reader-token-with-at-least-32-characters")
    reader_app = create_reader_app(ReaderSettings(logs, database, token))
    with TestClient(reader_app) as reader:

        def read_source(payload: dict[str, Any]) -> str:
            response = reader.post(
                "/internal/record",
                json=payload,
                headers={"Authorization": "Bearer " + token.read_text()},
            )
            assert response.headers["cache-control"] == "no-store"
            if response.status_code != 200:
                raise HTTPError(
                    "https://raw-reader:8443/internal/record",
                    response.status_code,
                    "Reader response",
                    Message(),
                    BytesIO(),
                )
            text: str = response.text
            return text

        settings = replace(configured(tmp_path), source_reader=read_source)
        with TestClient(create_app(settings)) as client:
            client.post("/login", json={"password": "synthetic-test-password"})
            receipt = client.post("/internal/events", json=event, headers=AUTH)
            assert receipt.status_code == 202
            task_id = receipt.json()["task_id"]
            task = terminal(client, task_id)
            evidence = task["evidence"][0]
            assert evidence["excerpt"] == command[:512]
            assert evidence["excerpt_truncated"] is True
            page = client.get(f"/tasks/{task_id}")
            assert 'data-raw-url="' + evidence["raw_url"] + '"' in page.text
            assert "Показать исходную запись" in page.text
            assert "Фрагмент сокращён до 512 символов" in page.text
            assert "&lt;script&gt;" in page.text
            assert '<script>alert("evidence-marker")</script>' not in page.text
            assert "raw-only-marker" not in page.text
            source = client.get(evidence["raw_url"])
            assert source.status_code == 200
            assert source.headers["content-type"].startswith("text/plain")
            assert source.text == raw
            assert "raw-only-marker" not in client.get("/tasks").text
            # A rename is not deletion, even before the collector's next scan.
            rotated = logs / "cowrie.json.1"
            (logs / "cowrie.json").rename(rotated)
            assert client.get(evidence["raw_url"]).text == raw
            journal.scan(logs)
            assert client.get(evidence["raw_url"]).text == raw
            # The original source disappears after its card/link were obtained.
            rotated.unlink()
            missing = client.get(evidence["raw_url"])
            assert missing.status_code == 410
            assert missing.headers["cache-control"] == "no-store"
            updated = client.get(f"/api/tasks/{task_id}").json()
            assert updated["evidence"][0]["source_status"] == "deleted"
            assert "raw_url" not in updated["evidence"][0]
            assert "excerpt" not in updated["evidence"][0]
            assert updated["event"]["command"]["text"] is None
            assert updated["analysis"] == task["analysis"]
            assert updated["state"] == task["state"]
            assert updated["audit"] == task["audit"]
            deleted_page = client.get(f"/tasks/{task_id}")
            assert "Источник удалён" in deleted_page.text
            assert "Показать исходную запись" not in deleted_page.text
            assert "evidence-marker" not in deleted_page.text
            assert "raw-only-marker" not in deleted_page.text
            # Confirmed deletion remains known even if the reader later goes down.
            with TestClient(
                create_app(replace(settings, source_reader=None))
            ) as restarted:
                restarted.post("/login", json={"password": "synthetic-test-password"})
                retained = restarted.get(f"/api/tasks/{task_id}").json()
                assert retained["evidence"][0]["source_status"] == "deleted"


@pytest.mark.parametrize(
    "disturbance", ["replacement", "symlink", "archive", "registry", "directory"]
)
def test_reader_uncertainty_does_not_claim_deletion_or_read_replacement(
    tmp_path: Path,
    disturbance: str,
) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    source = logs / "cowrie.json"
    record = {
        "eventid": "cowrie.command.input",
        "timestamp": "2026-10-24T10:00:00Z",
        "session": CONNECT["session"],
        "input": "pwd",
    }
    contents = json.dumps(CONNECT) + "\n" + json.dumps(record) + "\n"
    source.write_text(contents)
    database = tmp_path / "collector.db"
    journal = Journal(database, "source-uncertainty")
    journal.scan(logs)
    event = journal.pending()[0]
    token = tmp_path / "reader-token"
    token.write_text("synthetic-dedicated-reader-token")
    with TestClient(create_reader_app(ReaderSettings(logs, database, token))) as reader:

        def read_source(payload: dict[str, Any]) -> str:
            response = reader.post(
                "/internal/record",
                json=payload,
                headers={"Authorization": "Bearer " + token.read_text()},
            )
            if response.status_code != 200:
                raise HTTPError(
                    "https://raw-reader:8443/internal/record",
                    response.status_code,
                    "Source unavailable",
                    Message(),
                    BytesIO(),
                )
            text: str = response.text
            return text

        with TestClient(
            create_app(replace(configured(tmp_path), source_reader=read_source))
        ) as client:
            client.post("/login", json={"password": "synthetic-test-password"})
            receipt = client.post("/internal/events", json=event, headers=AUTH).json()
            task = terminal(client, receipt["task_id"])
            raw_url = task["evidence"][0]["raw_url"]
            if disturbance in ("replacement", "symlink"):
                source.rename(logs / "saved-original")
                if disturbance == "replacement":
                    source.write_text(contents.replace('"pwd"', '"replacement-marker"'))
                else:
                    target = tmp_path / "private.json"
                    target.write_text("replacement-marker")
                    source.symlink_to(target)
            elif disturbance == "archive":
                source.rename(logs / "cowrie.json.gz")
            elif disturbance == "registry":
                database.unlink()
            else:
                logs.rename(tmp_path / "unmounted-logs")
            response = client.get(raw_url)
            assert response.status_code == 503
            assert "replacement-marker" not in response.text
            metadata = client.get(f"/api/tasks/{task['task_id']}").json()
            assert metadata["evidence"][0]["source_status"] == "unavailable"
            assert "raw_url" not in metadata["evidence"][0]
            page = client.get(f"/tasks/{task['task_id']}")
            assert "Источник удалён" not in page.text
            assert "replacement-marker" not in page.text


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        ("SecOps", 200),
        ("DevOps", 200),
        ("Auditor", 200),
        ("Developer", 403),
        ("Service Principal", 403),
        ("unknown", 403),
    ],
)
def test_evidence_access_uses_server_assigned_human_role(
    tmp_path: Path, role: str, expected: int
) -> None:
    def read_source(event: dict[str, Any]) -> str:
        return '{"raw-only-marker": true}\n'

    settings = replace(configured(tmp_path), source_reader=read_source)
    event = {**command_event(), "raw_record_ref": "cowrie:synthetic-role-test"}
    with TestClient(create_app(settings)) as owner:
        owner.post("/login", json={"password": "synthetic-test-password"})
        receipt = owner.post("/internal/events", json=event, headers=AUTH).json()
        task = terminal(owner, receipt["task_id"])
        raw_url = task["evidence"][0]["raw_url"]
    settings = replace(settings, operator_role=role)
    with TestClient(create_app(settings)) as client:
        login = client.post("/login", json={"password": "synthetic-test-password"})
        assert login.json()["role"] == role
        for url in (
            "/tasks",
            f"/api/tasks/{task['task_id']}",
            f"/tasks/{task['task_id']}",
            raw_url,
        ):
            response = client.get(url)
            assert response.status_code == expected
            assert response.headers["cache-control"] == "no-store"
            if expected == 403:
                assert "raw-only-marker" not in response.text
        if expected == 200:
            assert client.get(raw_url).text == '{"raw-only-marker": true}\n'
            assert f"· {role} ·" in client.get(f"/tasks/{task['task_id']}").text


@pytest.mark.parametrize("explicit_read", [False, True])
def test_evidence_session_cannot_be_forged_or_kept_alive_by_polling(
    tmp_path: Path,
    explicit_read: bool,
) -> None:
    now = [1000.0]

    def read_source(event: dict[str, Any]) -> str:
        return '{"private-source-marker": true}\n'

    settings = replace(
        configured(tmp_path), clock=lambda: now[0], source_reader=read_source
    )
    with TestClient(create_app(settings)) as client:
        assert client.post(
            "/login", json={"password": "synthetic-test-password"}
        ).json() == {"role": "SecOps"}
        event = {**command_event(), "raw_record_ref": "cowrie:session-test"}
        receipt = client.post("/internal/events", json=event, headers=AUTH).json()
        task = terminal(client, receipt["task_id"])
        urls = [
            f"/api/tasks/{task['task_id']}",
            f"/tasks/{task['task_id']}",
            task["evidence"][0]["raw_url"],
        ]
        session = client.cookies.get("core_session")
        client.cookies.clear()
        for cookie in (None, "forged-session"):
            if cookie:
                client.cookies.set("core_session", cookie)
            for url in urls:
                denied = client.get(url, headers={**AUTH, "X-Role": "SecOps"})
                assert denied.status_code == 401
                assert denied.headers["cache-control"] == "no-store"
                assert "private-source-marker" not in denied.text
            client.cookies.clear()
        assert session is not None
        client.cookies.set("core_session", session)
        now[0] = 2799.0
        if explicit_read:
            viewed = client.get(urls[-1])
            assert viewed.status_code == 200
            assert "Max-Age=1800" in viewed.headers["set-cookie"]
            now[0] = 4598.0
        for url in urls:
            polled = client.get(url + "?poll=1")
            assert polled.status_code == 200
            assert polled.headers["cache-control"] == "no-store"
            assert "set-cookie" not in polled.headers
        now[0] += 1
        for url in urls:
            expired = client.get(url)
            assert expired.status_code == 401
            assert expired.headers["cache-control"] == "no-store"
            assert "private-source-marker" not in expired.text


def test_denied_role_cannot_be_overridden_by_client_or_rebound_on_restart(
    tmp_path: Path,
) -> None:
    settings = replace(configured(tmp_path), operator_role="Developer")
    with TestClient(create_app(settings)) as client:
        login = client.post(
            "/login",
            json={"password": "synthetic-test-password", "role": "SecOps"},
            headers={"X-Role": "SecOps"},
        )
        assert login.json() == {"role": "Developer"}
        session = client.cookies.get("core_session")
    with TestClient(create_app(replace(settings, operator_role="SecOps"))) as client:
        assert session is not None
        client.cookies.set("core_session", session)
        denied = client.get("/tasks?role=SecOps", headers={"X-Role": "SecOps"})
        assert denied.status_code == 403
        assert denied.headers["cache-control"] == "no-store"
        # Only a new, password-authenticated session receives the new server role.
        login = client.post("/login", json={"password": "synthetic-test-password"})
        assert login.json() == {"role": "SecOps"}
        assert client.get("/tasks").status_code == 200


def test_source_error_responses_do_not_cache_or_expose_raw_data(tmp_path: Path) -> None:
    def unavailable(event: dict[str, Any]) -> str:
        raise OSError("private-source-marker")

    settings = replace(configured(tmp_path), source_reader=unavailable)
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        receipt = client.post(
            "/internal/events",
            json={**command_event(), "raw_record_ref": "cowrie:unavailable"},
            headers=AUTH,
        ).json()
        task = terminal(client, receipt["task_id"])
        assert task["evidence"][0]["source_status"] == "unavailable"
        assert "raw_url" not in task["evidence"][0]
        raw_url = (
            f"/api/tasks/{task['task_id']}/evidence/{task['evidence'][0]['id']}/raw"
        )
        response = client.get(raw_url)
        assert response.status_code == 503
        assert response.headers["cache-control"] == "no-store"
        assert "private-source-marker" not in response.text
        response = client.get(
            raw_url.replace(
                task["evidence"][0]["id"], "00000000-0000-0000-0000-000000000000"
            )
        )
        assert response.status_code == 404
        assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("reader_status", [401, 404, 422, 503])
def test_unverified_source_is_not_claimed_deleted_and_recovers(
    tmp_path: Path,
    reader_status: int,
) -> None:
    offline = [True]

    def read_source(event: dict[str, Any]) -> str:
        if offline[0]:
            raise HTTPError(
                "https://raw-reader:8443/internal/record",
                reader_status,
                "Reader unavailable",
                Message(),
                BytesIO(),
            )
        return '{"recovered-source": true}\n'

    settings = replace(configured(tmp_path), source_reader=read_source)
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        receipt = client.post(
            "/internal/events",
            json={**command_event(), "raw_record_ref": "cowrie:recovery"},
            headers=AUTH,
        ).json()
        task = terminal(client, receipt["task_id"])
        assert task["evidence"][0]["source_status"] == "unavailable"
        assert "excerpt" not in task["evidence"][0]
        page = client.get(f"/tasks/{task['task_id']}")
        assert page.status_code == 200
        assert "Источник временно недоступен" in page.text
        assert "Источник удалён" not in page.text
        assert "Показать исходную запись" not in page.text
        offline[0] = False
        recovered = client.get(f"/api/tasks/{task['task_id']}").json()
        assert recovered["evidence"][0]["source_status"] == "available"
        assert (
            client.get(recovered["evidence"][0]["raw_url"]).text
            == '{"recovered-source": true}\n'
        )


def test_reader_rejects_human_and_collector_authority(tmp_path: Path) -> None:
    token = tmp_path / "reader-token"
    token.write_text("synthetic-dedicated-reader-token")
    settings = ReaderSettings(tmp_path, tmp_path / "registry.db", token)
    with TestClient(create_reader_app(settings)) as reader:
        for headers in ({}, AUTH, {"Authorization": "Bearer wrong"}):
            response = reader.post(
                "/internal/record", json=command_event(), headers=headers
            )
            assert response.status_code == 401
            assert response.headers["cache-control"] == "no-store"


def test_pre49_single_owner_session_survives_upgrade_without_extended_expiry(
    tmp_path: Path,
) -> None:
    now = [1001.0]
    settings = replace(configured(tmp_path), clock=lambda: now[0])
    cookie = "synthetic-pre49-session"
    # Historical SQLite input fixture; observe migration only through HTTP.
    with sqlite3.connect(settings.database) as old_database:
        old_database.execute(
            "CREATE TABLE sessions (digest TEXT PRIMARY KEY, last_active REAL NOT NULL)"
        )
        old_database.execute(
            "INSERT INTO sessions VALUES (?, ?)",
            (hashlib.sha256(cookie.encode()).hexdigest(), 1000.0),
        )
    with TestClient(create_app(settings)) as client:
        client.cookies.set("core_session", cookie)
        page = client.get("/tasks?poll=1")
        assert page.status_code == 200
        assert "· SecOps ·" in page.text
        assert page.headers["cache-control"] == "no-store"
        now[0] = 2800.0
        assert client.get("/tasks").status_code == 401
