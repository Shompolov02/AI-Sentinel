"""Controlled-time acceptance of retention through HTTP, CLI and stored bytes."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Event
from typing import Any

import pytest
from fastapi.testclient import TestClient
from test_command_guard import terminal
from test_core import AUTH, configured
from test_retention import captured_commands

from ai_sentinel_core.app import create_app


@pytest.mark.parametrize("view", ["api", "page", "raw"])
def test_reader_reply_crossing_fourteen_days_cannot_return_a_stale_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, view: str
) -> None:
    clock = [1792404000.0]
    _, events = captured_commands(tmp_path, clock, monkeypatch)
    delay, entered, release = Event(), Event(), Event()

    def reader(event: dict[str, Any]) -> str:
        if delay.is_set():
            entered.set()
            assert release.wait(5)
        return json.dumps(events[0])

    core = tmp_path / "core"
    core.mkdir()
    settings = replace(configured(core), clock=lambda: clock[0], source_reader=reader)
    with TestClient(create_app(settings)) as client, ThreadPoolExecutor() as pool:
        client.post("/login", json={"password": "synthetic-test-password"})
        task_id = client.post("/internal/events", json=events[0], headers=AUTH).json()[
            "task_id"
        ]
        item = terminal(client, task_id)
        clock[0] = 1793613599.0  # One second before the first receipt's deadline.
        client.post("/login", json={"password": "synthetic-test-password"})
        url = {
            "api": f"/api/tasks/{task_id}",
            "page": f"/tasks/{task_id}",
            "raw": item["evidence"][0]["raw_url"],
        }[view]
        delay.set()
        request = pool.submit(client.get, url)
        try:
            assert entered.wait(5)
            clock[0] = 1793613600.0
        finally:
            release.set()
        response = request.result()
        assert response.status_code == (503 if view == "raw" else 200)
        assert events[0]["command"]["text"] not in response.text
        if view == "api":
            expired = response.json()
            assert expired["event"]["command"]["text"] is None
            assert expired["analysis"] == item["analysis"]
            assert expired["evidence"][0]["source_status"] == "unavailable"
            assert "excerpt" not in expired["evidence"][0]
        elif view == "page":
            assert "Текст команды удалён по сроку хранения" in response.text
            assert "источник удалён" not in response.text.lower()
        for file in core.iterdir():
            if file.is_file():
                assert events[0]["command"]["text"].encode() not in file.read_bytes()


def test_full_local_lifecycle_uses_receipt_for_fourteen_and_thirty_day_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gzip
    import os
    import struct
    from email.message import Message
    from urllib.error import HTTPError

    from test_telemetry import CONNECT

    from ai_sentinel_core.raw_source import ReaderSettings, create_reader_app
    from ai_sentinel_core.retention import main
    from ai_sentinel_core.telemetry import Journal

    clock = [1792404000.0]  # 2026-10-19 10:00 UTC: first telemetry receipt.
    logs, downloads, core = (tmp_path / name for name in ("logs", "downloads", "core"))
    for directory in (logs, downloads, core):
        directory.mkdir()
    tty = logs / "tty"
    tty.mkdir()
    source = logs / "cowrie.json"
    journal = Journal(tmp_path / "collector.db", "lifecycle", clock=lambda: clock[0])
    old, fresh = "lifecycle-old-command-51", "lifecycle-fresh-command-51"
    service = logs / "cowrie.log"

    def write_session(session: str, marker: str, outcome: str) -> None:
        records = [
            {**CONNECT, "session": session, "timestamp": "2026-09-01T10:00:00Z"},
            {
                "eventid": "cowrie.command.input",
                "session": session,
                "timestamp": "2026-09-01T10:00:01Z",
                "input": marker,
            },
            {
                "eventid": f"cowrie.login.{outcome}",
                "session": session,
                "timestamp": "2026-09-01T10:00:02Z",
                "username": "synthetic",
                "password": marker,
            },
            {
                "eventid": "cowrie.session.file_upload",
                "session": session,
                "outfile": f"/var/lib/cowrie/downloads/{session}.copy",
            },
        ]
        with source.open("a") as stream:
            for record in records:
                stream.write(json.dumps(record) + "\n")
            if session == "old-session":
                stream.write("invalid-json-with-" + marker + "\n")
        journal.scan(logs)
        payload = (marker + "\n").encode()
        (tty / f"{session}.log").write_bytes(
            struct.pack("<iLiiLL", 3, 0, len(payload), 2, int(clock[0]), 0) + payload
        )
        (downloads / f"{session}.copy").write_bytes(payload)
        with service.open("a") as stream:
            stream.write(f"2026-09-01 [ssh,{session},192.0.2.10] CMD: {marker}\n")

    write_session("old-session", old, "success")
    clock[0] = 1792490400.0  # Another session is received a day later.
    write_session("fresh-session", fresh, "failed")
    events = journal.pending()
    assert len(events) == 4
    assert journal.status()["quarantine"]
    # Neither occurred_at nor file mtime is the retention clock.
    os.utime(source, (1823940000.0, 1823940000.0))
    (logs / "cowrie.json.1.gz").write_bytes(gzip.compress(source.read_bytes()))
    (logs / "cowrie.log.1.gz").write_bytes(gzip.compress(service.read_bytes()))
    clock[0] = 1792663200.0  # Core admission is delayed by three days.
    settings = replace(configured(core), clock=lambda: clock[0])
    reader_token = tmp_path / "reader-token"
    reader_token.write_text("synthetic-lifecycle-reader")
    monkeypatch.setenv("CORE_DB_PATH", str(settings.database))
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(journal.database))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "lifecycle")
    monkeypatch.setenv("COWRIE_LOG_DIR", str(logs))
    monkeypatch.setenv("COWRIE_DOWNLOAD_DIR", str(downloads))

    def maintain() -> None:
        for role in ("core", "raw", "collector"):
            assert main(["--role", role, "--once"], clock=lambda: clock[0]) == 0

    def stored_contents() -> list[bytes]:
        return [
            gzip.decompress(p.read_bytes()) if p.suffix == ".gz" else p.read_bytes()
            for p in tmp_path.rglob("*")
            if p.is_file()
        ]

    with TestClient(
        create_reader_app(
            ReaderSettings(logs, journal.database, reader_token, clock=lambda: clock[0])
        )
    ) as reader:

        def read(event: dict[str, Any]) -> str:
            result = reader.post(
                "/internal/record",
                json=event,
                headers={"Authorization": "Bearer synthetic-lifecycle-reader"},
            )
            if result.status_code != 200:
                raise HTTPError(
                    "http://reader/record",
                    result.status_code,
                    "source status",
                    Message(),
                    None,
                )
            return str(result.text)

        settings = replace(settings, source_reader=read)
        with TestClient(create_app(settings)) as client:
            client.post("/login", json={"password": "synthetic-test-password"})
            tasks = {}
            originals = {}
            for event in events:
                accepted = client.post("/internal/events", json=event, headers=AUTH)
                assert accepted.status_code == 202
                task_id = accepted.json()["task_id"]
                tasks[event["event_id"]] = task_id
                journal.acknowledge(event["event_id"], task_id)
                originals[task_id] = terminal(client, task_id)
            old_events = [
                event for event in events if event["session_id"] == "old-session"
            ]
            fresh_events = [
                event for event in events if event["session_id"] == "fresh-session"
            ]
            old_ids = [tasks[event["event_id"]] for event in old_events]
            raw_urls = [originals[task]["evidence"][0]["raw_url"] for task in old_ids]
            assert any(
                originals[task]["verdict"]["severity"] == "High"
                for task in old_ids
                if originals[task]["verdict"]
            )
            clock[0] = 1793613599.0  # Exact receipt + 14 days - one second.
            maintain()
            client.post("/login", json={"password": "synthetic-test-password"})
            for task in old_ids:
                assert (
                    client.get(f"/api/tasks/{task}").json()["evidence"][0][
                        "source_status"
                    ]
                    == "available"
                )
            assert any(old.encode() in content for content in stored_contents())
            chunks = tmp_path / "chunks"
            chunks.mkdir()
            (chunks / "stopped-buffer.flb").write_text(old + fresh)
            clock[0] = 1793613600.0
            maintain()
            assert all(old.encode() not in content for content in stored_contents())
            assert any(fresh.encode() in content for content in stored_contents())
            assert journal.status()["quarantine"] == []
            for task, url in zip(old_ids, raw_urls, strict=True):
                item = client.get(f"/api/tasks/{task}").json()
                assert item["analysis"] == originals[task]["analysis"]
                assert item["verdict"] == originals[task]["verdict"]
                assert item["evidence"][0]["source_status"] == "deleted"
                assert "excerpt" not in item["evidence"][0]
                assert client.get(url).status_code == 410
                page = client.get(f"/tasks/{task}")
                assert "Источник удалён" in page.text
                assert old not in page.text
            for event in fresh_events:
                item = client.get(f"/api/tasks/{tasks[event['event_id']]}").json()
                assert item["evidence"][0]["source_status"] == "available"
            replay = client.post("/internal/events", json=old_events[0], headers=AUTH)
            assert replay.status_code == 202
            assert replay.json()["task_id"] == old_ids[0]
            clock[0] = 1794995999.0  # Receipt + 30 days - one second.
            maintain()
            client.post("/login", json={"password": "synthetic-test-password"})
            for task in old_ids:
                assert client.get(f"/api/tasks/{task}").status_code == 200
            clock[0] = 1794996000.0
            maintain()
            for event in old_events:
                task = tasks[event["event_id"]]
                assert client.get(f"/api/tasks/{task}").status_code == 404
                assert (
                    client.post(
                        "/internal/events", json=event, headers=AUTH
                    ).status_code
                    == 410
                )
                for content in stored_contents():
                    assert task.encode() not in content
                    assert event["event_id"].encode() not in content
                    assert event["raw_record_ref"].encode() not in content
            for event in fresh_events:
                assert (
                    client.get(f"/api/tasks/{tasks[event['event_id']]}").status_code
                    == 200
                )
        with TestClient(create_app(settings)) as restarted:
            restarted.post("/login", json={"password": "synthetic-test-password"})
            assert all(
                restarted.get(f"/api/tasks/{task}").status_code == 404
                for task in old_ids
            )
            assert all(
                restarted.get(f"/api/tasks/{tasks[event['event_id']]}").status_code
                == 200
                for event in fresh_events
            )


@pytest.mark.parametrize("restart_at", [1793786400.0, 1795168800.0])
def test_queued_command_and_login_resume_safely_after_retention_and_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    restart_at: float,
) -> None:
    from email.message import Message
    from urllib.error import HTTPError

    from test_telemetry import LOGIN

    from ai_sentinel_core.raw_source import ReaderSettings, create_reader_app
    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    journal, commands = captured_commands(tmp_path, clock, monkeypatch)
    logs = tmp_path / "logs"
    with (logs / "cowrie.json").open("a") as stream:
        stream.write(json.dumps(LOGIN) + "\n")
    journal.scan(logs)  # Login is received at day 2.
    login = next(
        event for event in journal.pending() if event["event_type"] == "login_attempt"
    )
    core = tmp_path / "core"
    core.mkdir()
    token = tmp_path / "reader-token"
    token.write_text("synthetic-queue-reader")
    with TestClient(
        create_reader_app(
            ReaderSettings(logs, journal.database, token, clock=lambda: clock[0])
        )
    ) as reader:

        def read(event: dict[str, Any]) -> str:
            result = reader.post(
                "/internal/record",
                json=event,
                headers={"Authorization": "Bearer synthetic-queue-reader"},
            )
            if result.status_code != 200:
                raise HTTPError(
                    "http://reader/record",
                    result.status_code,
                    "source status",
                    Message(),
                    None,
                )
            return str(result.text)

        settings = replace(configured(core), clock=lambda: clock[0], source_reader=read)
        before = TestClient(create_app(settings))  # Intake without starting a worker.
        receipts = [
            before.post("/internal/events", json=event, headers=AUTH)
            for event in (commands[0], login)
        ]
        assert all(result.status_code == 202 for result in receipts)
        assert all(result.json()["state"] == "queued" for result in receipts)
        ids = [result.json()["task_id"] for result in receipts]
        before.close()
        clock[0] = restart_at
        monkeypatch.setenv("CORE_DB_PATH", str(settings.database))
        monkeypatch.setenv("COLLECTOR_DB_PATH", str(journal.database))
        monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
        monkeypatch.setenv("COWRIE_LOG_DIR", str(logs))
        for role in ("core", "raw", "collector"):
            assert main(["--role", role, "--once"], clock=lambda: clock[0]) == 0
        with TestClient(create_app(settings)) as resumed:
            resumed.post("/login", json={"password": "synthetic-test-password"})
            if restart_at == 1793786400.0:  # Login's exact 14-day deadline.
                command = terminal(resumed, ids[0])
                assert command["state"] == "failed"
                assert command["verdict"] is None
                assert command["analysis"]["reason_code"] == "text_expired"
                assert command["event"]["command"]["text"] is None
                assert command["history"] == ["queued", "processing", "failed"]
                safe_login = terminal(resumed, ids[1])
                assert safe_login["state"] == "completed"
                assert safe_login["verdict"]["severity"] == "Low"
                assert safe_login["verdict"]["analysis_method"] == "Rules"
                assert all(
                    item["evidence"][0]["source_status"] == "deleted"
                    for item in (command, safe_login)
                )
                assert "text_expired" in caplog.text
                assert "Срок хранения текста" in resumed.get("/tasks").text
            else:  # Both tasks passed their metadata deadlines before startup.
                assert all(
                    resumed.get(f"/api/tasks/{task}").status_code == 404 for task in ids
                )
                for file in core.iterdir():
                    if file.is_file():
                        assert all(
                            task.encode() not in file.read_bytes() for task in ids
                        )
        assert all(
            commands[0]["command"]["text"].encode() not in file.read_bytes()
            for file in core.iterdir()
            if file.is_file()
        )


@pytest.mark.parametrize("commit_at", [1793613599.0, 1793613600.0])
def test_guard_result_waiting_for_database_commit_is_rechecked_at_text_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, commit_at: float
) -> None:
    import sqlite3
    import subprocess
    import sys
    import time
    from threading import get_ident

    clock = [1792404000.0]
    _, events = captured_commands(tmp_path, clock, monkeypatch)
    entered, reply, release = (
        tmp_path / name for name in ("entered", "reply", "release")
    )
    checked, armed = Event(), Event()
    worker_thread: list[int | None] = [None]
    transport = """import json, pathlib, sys, time
for line in sys.stdin:
    pathlib.Path(sys.argv[1]).touch()
    while not pathlib.Path(sys.argv[3]).exists():
        time.sleep(0.01)
    pathlib.Path(sys.argv[2]).touch()
    print(json.dumps({"status":"blocked","score":1.0,"threshold":0.999,
        "revision":"8e0fdb567ad0d1ddac0c9c1819b182204db26867",
        "reason_code":"prompt_injection_detected"}), flush=True)
"""
    original_popen = subprocess.Popen

    def delayed_transport(args: Any, **kwargs: Any) -> Any:
        assert "ai_sentinel_core.guard_worker" in args
        worker_thread[0] = get_ident()
        return original_popen(
            [sys.executable, "-c", transport, str(entered), str(reply), str(release)],
            **kwargs,
        )

    def trusted_time() -> float:
        observed = clock[0]
        # Synchronize the trusted clock with the real inference transport,
        # then hold the real database writer across the deadline.
        if armed.is_set() and get_ident() == worker_thread[0] and reply.exists():
            checked.set()
        return observed

    monkeypatch.setattr(subprocess, "Popen", delayed_transport)
    clock[0] = 1793613599.0
    settings = replace(
        configured(tmp_path), clock=trusted_time, guard_model=tmp_path / "model"
    )
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        task_id = client.post("/internal/events", json=events[0], headers=AUTH).json()[
            "task_id"
        ]
        deadline = time.monotonic() + 5
        while not entered.exists():
            assert time.monotonic() < deadline
            time.sleep(0.01)
        try:
            with sqlite3.connect(settings.database) as locked:
                locked.execute("BEGIN IMMEDIATE")
                armed.set()
                release.touch()
                assert checked.wait(5)
                clock[0] = commit_at
                locked.rollback()
        finally:
            release.touch()
        item = terminal(client, task_id)
        if commit_at == 1793613600.0:
            assert item["state"] == "failed"
            assert item["verdict"] is None
            assert item["analysis"]["reason_code"] == "text_expired"
            assert item["event"]["command"]["text"] is None
            assert "Срок хранения текста" in client.get("/tasks").text
        else:
            assert item["state"] == "completed"
            assert item["verdict"]["severity"] == "High"
            assert item["event"]["command"]["text"] == events[0]["command"]["text"]
            clock[0] = 1793613600.0
            after = client.get(f"/api/tasks/{task_id}").json()
            assert after["state"] == "completed"
            assert after["verdict"] == item["verdict"]
            assert after["event"]["command"]["text"] is None


def test_storage_failure_at_deadline_is_not_reported_as_successful_erasure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import errno
    import sqlite3

    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    _, events = captured_commands(tmp_path, clock, monkeypatch)
    core = tmp_path / "core"
    core.mkdir()
    settings = replace(configured(core), clock=lambda: clock[0])
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        ids = [
            client.post("/internal/events", json=event, headers=AUTH).json()["task_id"]
            for event in events
        ]
        for task in ids:
            terminal(client, task)
        clock[0] = 1793613599.0
        client.post("/login", json={"password": "synthetic-test-password"})
        monkeypatch.setenv("CORE_DB_PATH", str(settings.database))
        clock[0] = 1793613600.0
        with monkeypatch.context() as fault:

            def unavailable(*args: Any, **kwargs: Any) -> None:
                raise OSError(errno.ENOSPC, "synthetic storage failure")

            fault.setattr(sqlite3, "connect", unavailable)
            assert main(["--role", "core", "--once"], clock=lambda: clock[0]) == 1
            response = client.get(f"/api/tasks/{ids[0]}")
            assert response.status_code == 503
            assert events[0]["command"]["text"] not in response.text
            assert (
                events[0]["command"]["text"].encode() in settings.database.read_bytes()
            )
            assert any(
                record.levelname == "CRITICAL"
                and "retention_cleanup_failed" in record.message
                for record in caplog.records
            )
        assert main(["--role", "core", "--once"], clock=lambda: clock[0]) == 0
        old = client.get(f"/api/tasks/{ids[0]}").json()
        fresh = client.get(f"/api/tasks/{ids[1]}").json()
        assert old["event"]["command"]["text"] is None
        assert old["evidence"][0]["source_status"] == "unavailable"
        assert fresh["event"]["command"]["text"] == events[1]["command"]["text"]
        for file in core.iterdir():
            if file.is_file():
                assert events[0]["command"]["text"].encode() not in file.read_bytes()
