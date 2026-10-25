"""Operator signals are checked through intake, authorized pages and local logs."""

import errno
import sqlite3
import time
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from test_command_guard import command_event, terminal
from test_core import AUTH, configured

from ai_sentinel_core.app import create_app
from core_fixtures import EVENT


def test_analysis_write_error_is_warning_when_failed_state_can_be_saved(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = configured(tmp_path)
    app = create_app(settings)
    seed = TestClient(app)
    seed.post("/login", json={"password": "synthetic-test-password"})
    task_id = seed.post("/internal/events", json=EVENT, headers=AUTH).json()["task_id"]
    cookies = dict(seed.cookies)
    seed.close()
    with sqlite3.connect(settings.database) as locked:
        locked.execute("BEGIN IMMEDIATE")
        with TestClient(app) as client:
            client.cookies.update(cookies)
            deadline = time.monotonic() + 12
            while "analysis_error" not in caplog.text:
                assert time.monotonic() < deadline
                time.sleep(0.01)
            locked.rollback()
            assert terminal(client, task_id)["state"] == "failed"
            page = client.get("/tasks")
            assert "Ошибка анализа задачи" in page.text
            assert "Предупреждение" in page.text
            assert "Нет текущих критических проблем" in page.text


def test_fallback_warning_is_visible_in_history_after_replay_and_restart(
    tmp_path: Path,
) -> None:
    settings = configured(tmp_path)
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        task_id = client.post(
            "/internal/events", json=command_event(), headers=AUTH
        ).json()["task_id"]
        assert terminal(client, task_id)["state"] == "failed"
        client.post("/internal/events", json=command_event(), headers=AUTH)
        page = client.get("/tasks")
        assert "История сигналов Core" in page.text
        assert "Резервный анализ: Guard недоступен" in page.text
        assert page.text.count("Резервный анализ: Guard недоступен") == 1
        assert "Предупреждение" in page.text
        assert "Нет текущих критических проблем" in page.text
        assert page.headers["cache-control"] == "no-store"
        assert "pwd" not in page.text
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        page = client.get("/tasks?q=not-a-task&state=completed")
        assert page.text.count("Резервный анализ: Guard недоступен") == 1
        assert f'href="/tasks/{task_id}"' in page.text


def test_full_intake_is_active_then_resolves_without_duplicate_history(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = configured(tmp_path)
    client = TestClient(create_app(settings))
    try:
        client.post("/login", json={"password": "synthetic-test-password"})
        for _ in range(1000):
            assert (
                client.post(
                    "/internal/events",
                    json={**EVENT, "event_id": str(uuid4())},
                    headers=AUTH,
                ).status_code
                == 202
            )
        for _ in range(2):
            assert (
                client.post("/internal/events", json=EVENT, headers=AUTH).status_code
                == 503
            )
            page = client.get("/tasks?q=not-a-task")
            assert "Приём остановлен: очередь заполнена" in page.text
            assert "Активно" in page.text
            assert "Критический" in page.text
    finally:
        client.close()
    with TestClient(create_app(settings)) as recovered:
        recovered.post("/login", json={"password": "synthetic-test-password"})
        deadline = time.monotonic() + 15
        while True:
            page = recovered.get("/tasks")
            if "Нет текущих критических проблем" in page.text:
                break
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert page.text.count("Приём остановлен: очередь заполнена") == 1
        assert "Устранено" in page.text
    assert any(
        record.levelname == "CRITICAL" and "intake_capacity_reached" in record.message
        for record in caplog.records
    )


def test_storage_outage_returns_safe_page_then_keeps_resolved_history(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = configured(tmp_path)
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        with sqlite3.connect(settings.database) as locked:
            locked.execute("BEGIN EXCLUSIVE")
            for url in ("/tasks", "/tasks?q=private-marker"):
                response = client.get(url)
                assert response.status_code == 503
                assert "Core недоступен" in response.text
                assert "проверьте журналы и контейнеры" in response.text
                assert "private-marker" not in response.text
                assert "Диск заполнен" not in response.text
                assert response.headers["cache-control"] == "no-store"
        page = client.get("/tasks")
        assert page.status_code == 200
        assert "Нет текущих критических проблем" in page.text
        assert page.text.count("Хранилище Core недоступно") == 1
        assert "Устранено" in page.text
        assert "storage_unavailable" in caplog.text
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        page = client.get("/tasks")
        assert page.text.count("Хранилище Core недоступно") == 1
        assert "Нет текущих критических проблем" in page.text


def test_confirmed_disk_full_is_distinct_from_generic_storage_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with TestClient(create_app(configured(tmp_path))) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        with monkeypatch.context() as fault:

            def no_space(*args: object, **kwargs: object) -> None:
                raise OSError(errno.ENOSPC, "private-path-and-secret")

            fault.setattr(sqlite3, "connect", no_space)
            response = client.get("/tasks")
            assert response.status_code == 503
            assert "private-path-and-secret" not in response.text
        page = client.get("/tasks")
        assert "Диск заполнен" in page.text
        assert "Нет текущих критических проблем" in page.text
        assert "disk_full" in caplog.text


def test_unwritten_failed_state_remains_critical_until_task_recovers(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = configured(tmp_path)
    app = create_app(settings)
    seed = TestClient(app)
    seed.post("/login", json={"password": "synthetic-test-password"})
    task_id = seed.post("/internal/events", json=EVENT, headers=AUTH).json()["task_id"]
    cookies = dict(seed.cookies)
    seed.close()
    with sqlite3.connect(settings.database) as locked:
        locked.execute("BEGIN IMMEDIATE")
        with TestClient(app) as client:
            client.cookies.update(cookies)
            deadline = time.monotonic() + 12
            while "storage_failure" not in caplog.text:
                assert time.monotonic() < deadline
                time.sleep(0.01)
            locked.rollback()
            page = client.get("/tasks")
            assert "Не удалось сохранить состояние задачи" in page.text
            assert "Активно" in page.text
            assert f'href="/tasks/{task_id}"' in page.text
    with TestClient(create_app(settings)) as recovered:
        recovered.post("/login", json={"password": "synthetic-test-password"})
        assert terminal(recovered, task_id)["state"] == "completed"
        page = recovered.get("/tasks")
        assert "Нет текущих критических проблем" in page.text
        assert page.text.count("Не удалось сохранить состояние задачи") == 1
        assert "Устранено" in page.text


@pytest.mark.parametrize(
    "role", ["SecOps", "DevOps", "Auditor", "Developer", "unknown"]
)
def test_alert_history_requires_authorized_human_session(
    tmp_path: Path, role: str
) -> None:
    from dataclasses import replace

    settings = configured(tmp_path)
    with TestClient(create_app(settings)) as owner:
        owner.post("/login", json={"password": "synthetic-test-password"})
        task_id = owner.post(
            "/internal/events", json=command_event(), headers=AUTH
        ).json()["task_id"]
        terminal(owner, task_id)
    with TestClient(create_app(replace(settings, operator_role=role))) as client:
        denied = client.get("/tasks", headers=AUTH)
        assert denied.status_code == 401
        assert "Резервный анализ" not in denied.text
        client.post("/login", json={"password": "synthetic-test-password"})
        page = client.get("/tasks", headers={"X-Role": "SecOps"})
        if role in ("SecOps", "DevOps", "Auditor"):
            assert page.status_code == 200
            assert "Резервный анализ: Guard недоступен" in page.text
        else:
            assert page.status_code == 403
            assert "Резервный анализ" not in page.text
        assert page.headers["cache-control"] == "no-store"
        assert client.post("/tasks", json={"acknowledge": True}).status_code == 405


def test_history_is_limited_to_latest_100_signals_and_omits_command_text(
    tmp_path: Path,
) -> None:
    from dataclasses import replace

    settings = replace(configured(tmp_path), clock=lambda: 1000.0)
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        ids = []
        for _ in range(101):
            receipt = client.post(
                "/internal/events",
                json={
                    **command_event("private-command-marker"),
                    "event_id": str(uuid4()),
                },
                headers=AUTH,
            ).json()
            ids.append(receipt["task_id"])
        deadline = time.monotonic() + 15
        while client.get(f"/api/tasks/{ids[-1]}").json()["state"] != "failed":
            assert time.monotonic() < deadline
            time.sleep(0.01)
        page = client.get("/tasks?q=no-matching-task")
        assert page.text.count("Резервный анализ: Guard недоступен") == 100
        assert ids[0] not in page.text
        assert ids[-1] in page.text
        assert "private-command-marker" not in page.text
