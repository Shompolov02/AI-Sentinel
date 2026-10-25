"""Search and filtering are observed through the authorized Core page."""

import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from test_command_guard import command_event, terminal
from test_core import AUTH, configured

from ai_sentinel_core.app import create_app
from core_fixtures import EVENT


def task_links(page: str) -> list[str]:
    table = re.search(r'<table aria-label="Задачи">(.*?)</table>', page, re.S)
    assert table is not None
    return re.findall(r'href="/tasks/([0-9a-f-]+)"', table.group(1))


def test_list_refresh_retains_search_and_state_without_renewing_session(
    tmp_path: Path,
) -> None:
    with TestClient(create_app(configured(tmp_path))) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        page = client.get("/tasks", params={"q": "ABC-12", "state": "failed"})
        form = Form()
        form.feed(page.text)
        refresh = next(f for f in form.fields if f.get("http-equiv") == "refresh")
        interval, url = str(refresh["content"]).split(";url=", 1)
        assert interval == "10"
        assert parse_qs(url.removeprefix("?")) == {
            "q": ["ABC-12"],
            "state": ["failed"],
            "poll": ["1"],
        }
        poll = client.get("/tasks" + url)
        assert poll.status_code == 200
        assert "set-cookie" not in poll.headers


@pytest.mark.parametrize("state", ["queued", "processing", "completed", "failed"])
def test_state_filter_does_not_show_queued_tasks_in_other_states(
    tmp_path: Path,
    state: str,
) -> None:
    # Without lifespan startup, accepted tasks remain queued through public HTTP.
    client = TestClient(create_app(configured(tmp_path)))
    try:
        client.post("/login", json={"password": "synthetic-test-password"})
        task_id = client.post("/internal/events", json=EVENT, headers=AUTH).json()[
            "task_id"
        ]
        page = client.get("/tasks", params={"state": state})
        assert page.status_code == 200
        assert task_links(page.text) == ([task_id] if state == "queued" else [])
        client.cookies.clear()
        assert (
            client.get("/tasks", params={"q": task_id, "state": state}).status_code
            == 401
        )
    finally:
        client.close()


def test_operator_searches_full_or_partial_number_across_saved_history(
    tmp_path: Path,
) -> None:
    with TestClient(create_app(configured(tmp_path))) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        oldest = client.post("/internal/events", json=EVENT, headers=AUTH).json()[
            "task_id"
        ]
        for _ in range(100):
            response = client.post(
                "/internal/events",
                json={**EVENT, "event_id": str(uuid4())},
                headers=AUTH,
            )
            assert response.status_code == 202
        assert terminal(client, oldest)["state"] == "completed"
        assert oldest not in task_links(client.get("/tasks").text)
        for query in (oldest, oldest[:18], oldest[10:28].upper(), f" {oldest} "):
            page = client.get("/tasks", params={"q": query, "state": "completed"})
            assert page.status_code == 200
            assert task_links(page.text) == [oldest]
            form = Form()
            form.feed(page.text)
            assert any(
                f.get("name") == "q" and f.get("value") == query.strip()
                for f in form.fields
            )
        assert (
            task_links(
                client.get("/tasks", params={"q": oldest, "state": "failed"}).text
            )
            == []
        )
        for query in (
            str(uuid4()),
            "%",
            "_",
            "' OR '1'='1",
            "<script>alert(50)</script>",
        ):
            page = client.get("/tasks", params={"q": query})
            assert page.status_code == 200
            assert task_links(page.text) == []
            assert "Задачи не найдены" in page.text
            assert "<script>alert(50)</script>" not in page.text


class Form(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.fields: list[dict[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("form", "input", "select", "option", "meta"):
            self.fields.append({"tag": tag, **dict(attrs)})


def test_operator_can_choose_state_in_read_only_filter_form(tmp_path: Path) -> None:
    with TestClient(create_app(configured(tmp_path))) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        page = client.get("/tasks", params={"state": "processing"})
        form = Form()
        form.feed(page.text)
        assert any(
            field.get("tag") == "form"
            and (field.get("method") or "").lower() == "get"
            and field.get("action") == "/tasks"
            for field in form.fields
        )
        assert any(field.get("name") == "state" for field in form.fields)
        options = [f for f in form.fields if f["tag"] == "option"]
        assert {f.get("value") for f in options} == {
            "",
            "queued",
            "processing",
            "completed",
            "failed",
        }
        assert [f.get("value") for f in options if "selected" in f] == ["processing"]
        assert "Задачи не найдены" in page.text


def test_operator_filters_real_tasks_by_state(tmp_path: Path) -> None:
    with TestClient(create_app(configured(tmp_path))) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        completed = client.post("/internal/events", json=EVENT, headers=AUTH).json()[
            "task_id"
        ]
        failed = client.post(
            "/internal/events",
            json={**command_event(), "event_id": str(uuid4())},
            headers=AUTH,
        ).json()["task_id"]
        assert terminal(client, completed)["state"] == "completed"
        assert terminal(client, failed)["state"] == "failed"

        page = client.get("/tasks", params={"state": "failed"})
        assert page.status_code == 200
        assert failed in task_links(page.text)
        assert completed not in task_links(page.text)
        assert "Не удалось оценить" in page.text

        page = client.get("/tasks", params={"state": "completed"})
        assert completed in task_links(page.text)
        assert failed not in task_links(page.text)
        assert "Low" in page.text
        assert "Отказ входа Cowrie" in page.text
        assert "UTC" in page.text
