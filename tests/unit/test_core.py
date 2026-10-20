from __future__ import annotations

import sys
from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parents[2] / "services/core"))

from ai_sentinel_core.app import Settings, create_app

sys.path.insert(0, str(Path(__file__).parents[2] / "tests"))
from core_fixtures import EVENT, TEST_VERIFIER  # noqa: E402

AUTH = {"Authorization": "Bearer synthetic-collector-token-for-tests"}


def test_collector_receives_task_number_without_waiting_for_analysis(
    tmp_path: Path,
) -> None:
    tokens = tmp_path / "tokens"
    tokens.write_text("synthetic-collector-token-for-tests\n")
    settings = Settings(tmp_path / "core.db", tokens, tmp_path / "password")
    with TestClient(create_app(settings)) as client:
        response = client.post("/internal/events", json=EVENT, headers=AUTH)
    assert response.status_code == 202
    assert UUID(response.json()["task_id"])
    assert response.json()["correlation_id"] == response.json()["task_id"]
    assert response.json()["state"] == "queued"


def test_intake_rejects_missing_and_wrong_collector_credentials(tmp_path: Path) -> None:
    tokens = tmp_path / "tokens"
    tokens.write_text("synthetic-collector-token-for-tests\n")
    with TestClient(
        create_app(Settings(tmp_path / "core.db", tokens, tmp_path / "hash"))
    ) as client:
        for headers in ({}, {"Authorization": "Bearer wrong"}):
            response = client.post("/internal/events", json=EVENT, headers=headers)
            assert response.status_code == 401


def test_intake_rejects_passwords_unknown_types_and_invalid_provenance(
    tmp_path: Path,
) -> None:
    tokens = tmp_path / "tokens"
    tokens.write_text("synthetic-collector-token-for-tests\n")
    invalid = [
        {**EVENT, "password": "must-never-be-accepted"},
        {**EVENT, "event_type": "command"},
        {**EVENT, "source_ip": "not-an-ip"},
        {**EVENT, "occurred_at": "2026-10-20T10:00:00"},
        {**EVENT, "login": {**EVENT["login"], "outcome": "success"}},
        {**EVENT, "login": {**EVENT["login"], "password": "not-allowed"}},
    ]
    with TestClient(
        create_app(Settings(tmp_path / "core.db", tokens, tmp_path / "hash"))
    ) as client:
        for event in invalid:
            response = client.post("/internal/events", json=event, headers=AUTH)
            assert response.status_code == 422
            assert "must-never-be-accepted" not in response.text


def configured(directory: Path) -> Settings:
    tokens = directory / "tokens"
    tokens.write_text("synthetic-collector-token-for-tests\n")
    verifier = directory / "password"
    verifier.write_text(TEST_VERIFIER)
    return Settings(directory / "core.db", tokens, verifier)


def test_secops_login_grants_read_only_page_and_separates_service_authority(
    tmp_path: Path,
) -> None:
    with TestClient(create_app(configured(tmp_path))) as client:
        assert client.get("/tasks").status_code == 401
        assert client.get("/tasks", headers=AUTH).status_code == 401
        assert client.post("/login", json={"password": "wrong"}).status_code == 401
        response = client.post("/login", json={"password": "synthetic-test-password"})
        assert response.status_code == 200
        assert "HttpOnly" in response.headers["set-cookie"]
        assert "SameSite=strict" in response.headers["set-cookie"]
        page = client.get("/tasks")
        assert page.status_code == 200
        assert "SecOps" in page.text
        assert "Список задач" in page.text
        assert client.post("/tasks", json={}).status_code == 405
        assert client.post("/internal/events", json=EVENT).status_code == 401


def test_failed_login_produces_explained_low_with_evidence_and_audited_states(
    tmp_path: Path,
) -> None:
    import time

    with TestClient(create_app(configured(tmp_path))) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        accepted = client.post("/internal/events", json=EVENT, headers=AUTH)
        task_id = accepted.json()["task_id"]
        deadline = time.monotonic() + 3
        while True:
            response = client.get(f"/api/tasks/{task_id}")
            assert response.status_code == 200
            task = response.json()
            if task["state"] == "completed" or time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        assert task["state"] == "completed"
        assert task["history"] == ["queued", "processing", "completed"]
        verdict = task["verdict"]
        assert verdict["severity"] == "Low"
        assert verdict["analysis_method"] == "Rules"
        assert verdict["guard_result"] == "not_applicable"
        assert verdict["mitre_attack"] is None
        assert "отказ" in verdict["reason"].lower()
        assert task["evidence"][0]["raw_record_ref"] == "synthetic:login-1"
        assert verdict["evidence_ids"] == [task["evidence"][0]["id"]]
        assert [entry["action"] for entry in task["audit"]] == [
            "event_accepted",
            "processing",
            "verdict_created",
            "completed",
        ]
        page = client.get(f"/tasks/{task_id}")
        assert page.status_code == 200
        assert "Low" in page.text and task_id in page.text
        assert "синтетический" in page.text.lower()


def test_duplicate_delivery_preserves_task_result_and_audit_after_restart(
    tmp_path: Path,
) -> None:
    import time

    settings = configured(tmp_path)
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        first = client.post("/internal/events", json=EVENT, headers=AUTH).json()
        task_id = first["task_id"]
        for _ in range(100):
            original = client.get(f"/api/tasks/{task_id}").json()
            if original["state"] == "completed":
                break
            time.sleep(0.01)
        assert original["state"] == "completed"
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        repeated = client.post("/internal/events", json=EVENT, headers=AUTH)
        assert repeated.status_code == 202
        assert repeated.json()["task_id"] == task_id
        assert client.get(f"/api/tasks/{task_id}").json() == original
        conflict = client.post(
            "/internal/events", json={**EVENT, "sensor_id": "changed"}, headers=AUTH
        )
        assert conflict.status_code == 409


def test_idle_session_renews_on_activity_and_expires_at_thirty_minutes(
    tmp_path: Path,
) -> None:
    from dataclasses import replace

    now = [1000.0]
    settings = replace(configured(tmp_path), clock=lambda: now[0])
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        cookie = client.cookies.get("core_session")
        now[0] += 1799
        active = client.get("/tasks")
        assert active.status_code == 200
        assert "Max-Age=1800" in active.headers.get("set-cookie", "")
        now[0] += 1799
        assert client.get("/tasks").status_code == 200
        now[0] += 1800
        assert client.get("/tasks").status_code == 401
        client.cookies.set("core_session", cookie)
        assert client.get("/tasks").status_code == 401


def test_login_page_is_usable_and_protected_pages_do_not_cache_untrusted_text(
    tmp_path: Path,
) -> None:
    with TestClient(create_app(configured(tmp_path))) as client:
        page = client.get("/login")
        assert page.status_code == 200
        assert 'type="password"' in page.text
        assert client.get("/login.js").status_code == 200
        client.post("/login", json={"password": "synthetic-test-password"})
        event = {
            **EVENT,
            "login": {**EVENT["login"], "username": "<script>alert(1)</script>"},
        }
        task_id = client.post("/internal/events", json=event, headers=AUTH).json()[
            "task_id"
        ]
        page = client.get(f"/tasks/{task_id}")
        assert page.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
        assert "<script>alert(1)</script>" not in page.text
        assert "&lt;script&gt;" in page.text


def test_automatic_refresh_does_not_extend_idle_session(tmp_path: Path) -> None:
    from dataclasses import replace

    now = [1000.0]
    settings = replace(configured(tmp_path), clock=lambda: now[0])
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        now[0] += 1799
        poll = client.get("/tasks?poll=1")
        assert poll.status_code == 200
        assert "set-cookie" not in poll.headers
        now[0] += 1
        assert client.get("/tasks?poll=1").status_code == 401


def test_committed_queue_recovers_after_restart_and_rejects_over_capacity(
    tmp_path: Path,
) -> None:
    from uuid import uuid4

    settings = configured(tmp_path)
    # A client without lifespan keeps analysis stopped: acceptance must stay durable
    # and bounded even when the worker has not started yet.
    client = TestClient(create_app(settings))
    first = client.post("/internal/events", json=EVENT, headers=AUTH).json()["task_id"]
    for _ in range(999):
        accepted = client.post(
            "/internal/events", json={**EVENT, "event_id": str(uuid4())}, headers=AUTH
        )
        assert accepted.status_code == 202
    blocked = client.post(
        "/internal/events", json={**EVENT, "event_id": str(uuid4())}, headers=AUTH
    )
    assert blocked.status_code == 503
    assert (
        client.post("/internal/events", json=EVENT, headers=AUTH).json()["task_id"]
        == first
    )
    client.close()
    with TestClient(create_app(settings)) as recovered:
        recovered.post("/login", json={"password": "synthetic-test-password"})
        task = recovered.get(f"/api/tasks/{first}").json()
        assert task["state"] == "completed"
        assert task["verdict"]["severity"] == "Low"


def test_collector_token_rotation_accepts_overlap_then_revokes_old_token(
    tmp_path: Path,
) -> None:
    settings = configured(tmp_path)
    with TestClient(create_app(settings)) as client:
        settings.tokens.write_text(
            "synthetic-collector-token-for-tests\nsynthetic-next-collector-token-for-tests\n"
        )
        next_auth = {"Authorization": "Bearer synthetic-next-collector-token-for-tests"}
        assert (
            client.post("/internal/events", json=EVENT, headers=next_auth).status_code
            == 202
        )
        settings.tokens.write_text("synthetic-next-collector-token-for-tests\n")
        assert (
            client.post("/internal/events", json=EVENT, headers=AUTH).status_code == 401
        )
        assert (
            client.post("/internal/events", json=EVENT, headers=next_auth).status_code
            == 202
        )


def test_storage_failure_never_acknowledges_an_uncommitted_event(
    tmp_path: Path,
) -> None:
    import sqlite3

    settings = configured(tmp_path)
    with TestClient(create_app(settings)) as client:
        with sqlite3.connect(settings.database) as unavailable:
            unavailable.execute("BEGIN EXCLUSIVE")
            response = client.post("/internal/events", json=EVENT, headers=AUTH)
            assert response.status_code == 503
        assert (
            client.post("/internal/events", json=EVENT, headers=AUTH).status_code == 202
        )


def test_successful_login_is_audited_but_failed_login_is_not(tmp_path: Path) -> None:
    from dataclasses import replace

    now = [1000.0]
    settings = replace(configured(tmp_path), clock=lambda: now[0])
    with TestClient(create_app(settings)) as client:
        assert client.post("/login", json={"password": "wrong"}).status_code == 401
        now[0] = 2000.0
        assert (
            client.post(
                "/login", json={"password": "synthetic-test-password"}
            ).status_code
            == 200
        )
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        page = client.get("/tasks")
        assert "01.01.1970 00:16:40 UTC" not in page.text
        assert page.text.count("01.01.1970 00:33:20 UTC") == 2
        assert "synthetic-test-password" not in page.text


def test_contract_version_is_an_integer_not_a_boolean(tmp_path: Path) -> None:
    with TestClient(create_app(configured(tmp_path))) as client:
        response = client.post(
            "/internal/events", json={**EVENT, "schema_version": True}, headers=AUTH
        )
        assert response.status_code == 422
