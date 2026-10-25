"""Automatic task refresh is observed through authenticated HTTP pages."""

from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_command_guard import command_event, terminal
from test_core import AUTH, configured
from test_core_list import Form

from ai_sentinel_core.app import create_app
from core_fixtures import EVENT


@pytest.mark.parametrize("event_type", ["login", "command"])
def test_queued_card_refreshes_to_terminal_result_without_changing_task(
    tmp_path: Path, event_type: str
) -> None:
    settings = configured(tmp_path)
    event = EVENT if event_type == "login" else command_event()
    # No lifespan startup: the publicly accepted task remains queued.
    client = TestClient(create_app(settings))
    try:
        client.post("/login", json={"password": "synthetic-test-password"})
        task_id = client.post("/internal/events", json=event, headers=AUTH).json()[
            "task_id"
        ]
        page = client.get(f"/tasks/{task_id}")
        assert "В очереди" in page.text
        form = Form()
        form.feed(page.text)
        assert any(f.get("content") == "10;url=?poll=1" for f in form.fields)
    finally:
        client.close()

    # Recovery runs the real worker; no task state or database is edited by the test.
    with TestClient(create_app(settings)) as recovered:
        recovered.post("/login", json={"password": "synthetic-test-password"})
        task = terminal(recovered, task_id)
        expected = "completed" if event_type == "login" else "failed"
        assert task["state"] == expected
        page = recovered.get(f"/tasks/{task_id}?poll=1")
        assert page.status_code == 200
        assert page.headers["cache-control"] == "no-store"
        assert "set-cookie" not in page.headers
        assert 'http-equiv="refresh"' not in page.text
        assert (
            "Готов вердикт" if event_type == "login" else "Не удалось оценить"
        ) in page.text
        assert recovered.get(f"/api/tasks/{task_id}?poll=1").json() == task
        assert recovered.post(f"/tasks/{task_id}", json={}).status_code == 405


def test_background_refresh_of_list_card_and_api_cannot_keep_session_alive(
    tmp_path: Path,
) -> None:
    now = [1000.0]
    settings = replace(configured(tmp_path), clock=lambda: now[0])
    client = TestClient(create_app(settings))
    try:
        client.post("/login", json={"password": "synthetic-test-password"})
        task_id = client.post("/internal/events", json=EVENT, headers=AUTH).json()[
            "task_id"
        ]
        urls = [
            f"/tasks?q={task_id[:12]}&state=queued&poll=1",
            f"/tasks/{task_id}?poll=1",
            f"/api/tasks/{task_id}?poll=1",
        ]
        for elapsed in (10, 900, 1799):
            now[0] = 1000 + elapsed
            for url in urls:
                response = client.get(url)
                assert response.status_code == 200
                assert "set-cookie" not in response.headers
        now[0] = 2800
        for url in urls:
            response = client.get(url)
            assert response.status_code == 401
            assert response.headers["cache-control"] == "no-store"
            assert 'http-equiv="refresh"' not in response.text
            assert task_id not in response.text
        assert "Войти" in client.get(urls[1]).text
    finally:
        client.close()
