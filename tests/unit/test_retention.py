"""Retention is observed through intake/pages, the maintenance CLI and files."""

from __future__ import annotations

import json
import sqlite3
import struct
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError

import pytest
from fastapi.testclient import TestClient
from test_command_guard import terminal
from test_core import AUTH, configured
from test_telemetry import CONNECT

from ai_sentinel_core import telemetry
from ai_sentinel_core.app import create_app
from ai_sentinel_core.telemetry import Journal


def captured_commands(
    directory: Path,
    clock: list[float],
    monkeypatch: pytest.MonkeyPatch,
    texts: tuple[str, str] = (
        "old-unique-retention-command-51",
        "fresh-unique-command-51",
    ),
) -> tuple[Journal, list[dict[str, Any]]]:
    class CaptureTime(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> CaptureTime:
            return cls.fromtimestamp(clock[0], tz=tz)

    monkeypatch.setattr(telemetry, "datetime", CaptureTime)
    logs = directory / "logs"
    logs.mkdir()
    raw = logs / "cowrie.json"
    raw.write_text(json.dumps(CONNECT) + "\n")
    journal = Journal(
        directory / "collector.db", "retention-test", clock=lambda: clock[0]
    )
    for text in texts:
        with raw.open("a") as stream:
            stream.write(
                json.dumps(
                    {
                        "eventid": "cowrie.command.input",
                        "session": CONNECT["session"],
                        "timestamp": datetime.fromtimestamp(
                            clock[0], timezone.utc
                        ).isoformat(),
                        "input": text,
                    }
                )
                + "\n"
            )
        journal.scan(logs)
        clock[0] += 86400
    return journal, journal.pending()


def test_text_is_erased_at_first_receipt_deadline_but_fresh_command_survives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [1792404000.0]
    _, events = captured_commands(tmp_path, clock, monkeypatch)
    core = tmp_path / "core"
    core.mkdir()
    settings = replace(configured(core), clock=lambda: clock[0])
    with TestClient(create_app(settings)) as client:
        ids = [
            client.post("/internal/events", json=event, headers=AUTH).json()["task_id"]
            for event in events
        ]
        client.post("/login", json={"password": "synthetic-test-password"})
        original = terminal(client, ids[0])
        terminal(client, ids[1])
        clock[0] = 1793613599.0  # First receipt + fourteen days - one second.
        client.post("/login", json={"password": "synthetic-test-password"})
        assert events[0]["command"]["text"] in client.get(f"/tasks/{ids[0]}").text
        clock[0] += 1
        from ai_sentinel_core.retention import main

        monkeypatch.setenv("CORE_DB_PATH", str(settings.database))
        assert main(["--role", "core", "--once"], clock=lambda: clock[0]) == 0
        expired = client.get(f"/api/tasks/{ids[0]}").json()
        assert expired["event"]["command"]["text"] is None
        assert expired["analysis"] == original["analysis"]
        assert events[0]["command"]["text"] not in client.get(f"/tasks/{ids[0]}").text
        assert client.get(f"/api/tasks/{ids[1]}").json()["event"]["command"] == {
            "text": events[1]["command"]["text"]
        }
        for file in core.rglob("*"):
            if file.is_file():
                assert events[0]["command"]["text"].encode() not in file.read_bytes()


def test_idle_core_erases_text_without_page_traffic_and_rejects_expired_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [1792404000.0]
    _, events = captured_commands(tmp_path, clock, monkeypatch)
    core = tmp_path / "core"
    core.mkdir()
    settings = replace(configured(core), clock=lambda: clock[0])
    marker = events[0]["command"]["text"].encode()
    with TestClient(create_app(settings)) as client:
        accepted = client.post("/internal/events", json=events[0], headers=AUTH)
        assert accepted.status_code == 202
        clock[0] = 1793613600.0
        for _ in range(250):
            if all(marker not in f.read_bytes() for f in core.iterdir() if f.is_file()):
                break
            time.sleep(0.01)
        else:
            raise AssertionError("Idle Core retained expired command text")
        other = {**events[0], "event_id": "aa4a9660-4035-4394-b037-a4b4b3ce442b"}
        assert (
            client.post("/internal/events", json=other, headers=AUTH).status_code == 410
        )


def test_expired_command_cannot_escape_through_reader_or_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [1792404000.0]
    _, events = captured_commands(tmp_path, clock, monkeypatch)
    settings = replace(
        configured(tmp_path),
        clock=lambda: clock[0],
        source_reader=lambda event: json.dumps(events[0]),
    )
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        receipt = client.post("/internal/events", json=events[0], headers=AUTH).json()
        task_id = receipt["task_id"]
        original = terminal(client, task_id)
        raw_url = original["evidence"][0]["raw_url"]
        clock[0] = 1793613600.0
        client.post("/login", json={"password": "synthetic-test-password"})
        item = client.get(f"/api/tasks/{task_id}")
        assert item.status_code == 200
        assert events[0]["command"]["text"] not in item.text
        assert item.json()["evidence"][0]["source_status"] == "unavailable"
        assert "raw_url" not in item.json()["evidence"][0]
        page = client.get(f"/tasks/{task_id}")
        assert "источник удалён" not in page.text.lower()
        assert "Текст команды удалён по сроку хранения" in page.text
        source = client.get(raw_url)
        assert source.status_code == 503  # A deadline alone is not deletion proof.
        assert events[0]["command"]["text"] not in source.text
        repeat = client.post("/internal/events", json=events[0], headers=AUTH)
        assert repeat.status_code == 202
        assert repeat.json()["task_id"] == task_id
        assert (
            client.get(f"/api/tasks/{task_id}").json()["analysis"]
            == original["analysis"]
        )
        for suffix in ("", "-journal", "-wal", "-shm"):
            file = Path(str(settings.database) + suffix)
            if file.exists():
                assert events[0]["command"]["text"].encode() not in file.read_bytes()


def test_collector_erases_expired_outbox_and_keeps_fresh_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    clock = [1792404000.0]
    journal, events = captured_commands(tmp_path, clock, monkeypatch)
    clock[0] = 1793613600.0
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "collector.db"))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    from ai_sentinel_core.retention import main

    assert main(["--role", "collector", "--once"], clock=lambda: clock[0]) == 0
    assert [event["event_id"] for event in journal.pending()] == [events[1]["event_id"]]
    assert "buffer_event_expired" in caplog.text
    assert events[0]["command"]["text"] not in caplog.text
    for file in tmp_path.glob("collector.db*"):
        assert events[0]["command"]["text"].encode() not in file.read_bytes()


def test_raw_cleanup_preserves_fresh_offsets_and_an_open_cowrie_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_sentinel_core.raw_source import ReaderSettings, create_reader_app
    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    journal, events = captured_commands(tmp_path, clock, monkeypatch)
    tokens = tmp_path / "reader-tokens"
    tokens.write_text("synthetic-reader-token")
    settings = ReaderSettings(
        tmp_path / "logs", tmp_path / "collector.db", tokens, clock=lambda: clock[0]
    )
    auth = {"Authorization": "Bearer synthetic-reader-token"}
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(settings.registry))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    monkeypatch.setenv("COWRIE_LOG_DIR", str(settings.logs))
    with TestClient(create_reader_app(settings)) as client:
        assert (
            client.post("/internal/record", json=events[0], headers=auth).status_code
            == 200
        )
        clock[0] = 1793613600.0
        raw = settings.logs / "cowrie.json"
        with raw.open("ab") as writer:
            assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
            assert (
                client.post(
                    "/internal/record", json=events[0], headers=auth
                ).status_code
                == 410
            )
            fresh = client.post("/internal/record", json=events[1], headers=auth)
            assert fresh.status_code == 200
            assert events[1]["command"]["text"] in fresh.text
            writer.write(
                (
                    json.dumps(
                        {
                            "eventid": "cowrie.command.input",
                            "session": CONNECT["session"],
                            "timestamp": "2026-11-02T00:00:00Z",
                            "input": "after-cleanup-marker",
                        }
                    )
                    + "\n"
                ).encode()
            )
            writer.flush()
            journal.scan(settings.logs)
        assert "after-cleanup-marker" in json.dumps(journal.pending())
        assert events[0]["command"]["text"].encode() not in raw.read_bytes()
        assert events[1]["raw_record_ref"] in {
            event["raw_record_ref"] for event in journal.pending()
        }


def test_core_retains_real_deletion_proof_after_text_is_erased(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_sentinel_core.raw_source import ReaderSettings, create_reader_app
    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    _, events = captured_commands(tmp_path, clock, monkeypatch)
    token = tmp_path / "reader-token"
    token.write_text("synthetic-reader-token")
    reader_settings = ReaderSettings(
        tmp_path / "logs", tmp_path / "collector.db", token, clock=lambda: clock[0]
    )
    with TestClient(create_reader_app(reader_settings)) as reader:

        def read(event: dict[str, Any]) -> str:
            response = reader.post(
                "/internal/record",
                json=event,
                headers={"Authorization": "Bearer synthetic-reader-token"},
            )
            if response.status_code != 200:
                raise HTTPError(
                    "https://raw-reader/internal/record",
                    response.status_code,
                    "source status",
                    response.headers,
                    None,
                )
            return str(response.text)

        core = tmp_path / "core"
        core.mkdir()
        settings = replace(configured(core), clock=lambda: clock[0], source_reader=read)
        with TestClient(create_app(settings)) as client:
            client.post("/login", json={"password": "synthetic-test-password"})
            task_id = client.post(
                "/internal/events", json=events[0], headers=AUTH
            ).json()["task_id"]
            original = terminal(client, task_id)
            url = original["evidence"][0]["raw_url"]
            clock[0] = 1793613600.0
            monkeypatch.setenv("COLLECTOR_DB_PATH", str(reader_settings.registry))
            monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
            monkeypatch.setenv("COWRIE_LOG_DIR", str(reader_settings.logs))
            assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
            client.post("/login", json={"password": "synthetic-test-password"})
            item = client.get(f"/api/tasks/{task_id}").json()
            assert item["evidence"][0]["source_status"] == "deleted"
            assert item["analysis"] == original["analysis"]
            assert client.get(url).status_code == 410
            assert "Источник удалён" in client.get(f"/tasks/{task_id}").text
        with TestClient(create_app(replace(settings, source_reader=None))) as restarted:
            restarted.post("/login", json={"password": "synthetic-test-password"})
            assert restarted.get(url).status_code == 410


def test_tty_and_service_log_expire_from_session_start_but_primary_text_survives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    _, events = captured_commands(tmp_path, clock, monkeypatch)
    logs = tmp_path / "logs"
    tty = logs / "tty"
    tty.mkdir()
    transcript = tty / "session-1.log"
    frames = []
    lines = []
    for event in events:
        stamp = int(
            datetime.fromisoformat(
                event["received_at"].replace("Z", "+00:00")
            ).timestamp()
        )
        data = (event["command"]["text"] + "\n").encode()
        frames.append(struct.pack("<iLiiLL", 3, 0, len(data), 1, stamp, 0) + data)
        lines.append(
            f"{event['received_at']} [session-1] CMD: {event['command']['text']}\n"
        )
    transcript.write_bytes(b"".join(frames))
    service_log = logs / "cowrie.log"
    service_log.write_text("".join(lines))
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "collector.db"))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    monkeypatch.setenv("COWRIE_LOG_DIR", str(logs))
    assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
    clock[0] = 1793613600.0
    with transcript.open("ab") as active:
        assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
        active.write(struct.pack("<iLiiLL", 2, 0, 0, 0, int(clock[0]), 0))
    for file in (transcript, service_log):
        assert events[0]["command"]["text"].encode() not in file.read_bytes()
        assert events[1]["command"]["text"].encode() not in file.read_bytes()
    assert events[1]["command"]["text"].encode() in (logs / "cowrie.json").read_bytes()
    data = transcript.read_bytes()
    assert struct.unpack("<iLiiLL", data[:24]) == (
        3,
        0,
        len(events[0]["command"]["text"]) + 1,
        1,
        1792404000,
        0,
    )


def test_collector_rebuilds_stopped_chunks_from_durable_fresh_outbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    journal, events = captured_commands(tmp_path, clock, monkeypatch)
    chunks = tmp_path / "chunks" / "stdin.0"
    chunks.mkdir(parents=True)
    # Opaque storage boundary: a chunk may contain both old and fresh records.
    (chunks / "buffer.flb").write_bytes(json.dumps(events).encode())
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "collector.db"))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    clock[0] = 1793613600.0
    assert main(["--role", "collector", "--once"], clock=lambda: clock[0]) == 0
    for file in (tmp_path / "chunks").rglob("*"):
        if file.is_file():
            assert events[0]["command"]["text"].encode() not in file.read_bytes()
    assert [e["event_id"] for e in journal.pending()] == [events[1]["event_id"]]


def test_legacy_database_migration_scrubs_expired_unknown_and_freed_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [1792404000.0]
    _, events = captured_commands(tmp_path, clock, monkeypatch)
    core = tmp_path / "core"
    core.mkdir()
    settings = replace(configured(core), clock=lambda: 1793613600.0)
    # A saved pre-retention SQLite file is the migration input boundary.
    # Assertions below use HTTP and file bytes, not internal SELECT queries.
    with sqlite3.connect(settings.database) as db:
        db.execute("PRAGMA secure_delete=OFF")
        db.execute(
            "CREATE TABLE tasks (id TEXT PRIMARY KEY,event_id TEXT UNIQUE NOT NULL,"
            "event TEXT NOT NULL,state TEXT NOT NULL,created REAL NOT NULL,"
            "verdict TEXT,evidence TEXT)"
        )
        for index, event in enumerate(events):
            payload = {**event}
            if index == 1:
                payload.pop("received_at")
            db.execute(
                "INSERT INTO tasks VALUES (?,?,?,'completed',?,?,?)",
                (
                    f"legacy-{index}",
                    event["event_id"],
                    json.dumps(payload, sort_keys=True),
                    1792404000.0,
                    json.dumps(
                        {"severity": "High", "reason": "Сохранённое объяснение"}
                    ),
                    "[]",
                ),
            )
        db.execute("CREATE TABLE old_payload (payload TEXT)")
        db.execute(
            "INSERT INTO old_payload VALUES (?)", ("freed-retention-marker-51" * 500,)
        )
        db.execute("DELETE FROM old_payload")
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        for index in (0, 1):
            item = client.get(f"/api/tasks/legacy-{index}").json()
            assert item["event"]["command"]["text"] is None
            assert item["verdict"]["reason"] == "Сохранённое объяснение"
    for file in core.iterdir():
        if file.is_file():
            data = file.read_bytes()
            for marker in (
                "freed-retention-marker-51",
                *(e["command"]["text"] for e in events),
            ):
                assert marker.encode() not in data


def test_queued_command_expires_before_worker_start_without_guard_analysis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [1792404000.0]
    _, events = captured_commands(tmp_path, clock, monkeypatch)
    settings = replace(configured(tmp_path), clock=lambda: clock[0])
    app = create_app(settings)
    # Intake remains a public HTTP boundary; lifespan starts only after expiry.
    before_startup = TestClient(app)
    task_id = before_startup.post(
        "/internal/events", json=events[0], headers=AUTH
    ).json()["task_id"]
    clock[0] = 1793613600.0
    with TestClient(app) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        item = terminal(client, task_id)
        assert item["state"] == "failed"
        assert item["analysis"]["reason_code"] == "text_expired"
        assert item["event"]["command"]["text"] is None
        assert "text_expired" in json.dumps(item["audit"])


def test_identical_primary_commands_keep_distinct_deadlines_after_tty_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    _, events = captured_commands(tmp_path, clock, monkeypatch, ("pwd", "pwd"))
    tty = tmp_path / "logs" / "tty"
    tty.mkdir()
    path = tty / "session-1.log"

    def frame(stamp: int) -> bytes:
        return struct.pack("<iLiiLL", 3, 0, 4, 1, stamp, 0) + b"pwd\n"

    path.write_bytes(frame(1792404000) + frame(1792490400))
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "collector.db"))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    monkeypatch.setenv("COWRIE_LOG_DIR", str(tmp_path / "logs"))
    assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
    clock[0] = 1793613600.0
    assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
    assert path.read_bytes()[24:28] == b"   \n"
    assert path.read_bytes()[52:56] == b"   \n"
    remaining = [
        json.loads(line)
        for line in (tmp_path / "logs/cowrie.json").read_text().splitlines()
        if line.strip()
    ]
    assert [record["input"] for record in remaining] == ["pwd"]


def test_collector_migration_scrubs_old_free_pages_at_storage_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_sentinel_core.retention import main

    database = tmp_path / "collector.db"
    with sqlite3.connect(database) as db:
        db.execute("PRAGMA secure_delete=OFF")
        db.execute("CREATE TABLE discarded(payload TEXT)")
        db.execute(
            "INSERT INTO discarded VALUES (?)", ("old-free-collector-marker" * 1000,)
        )
        db.execute("DELETE FROM discarded")
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(database))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    assert main(["--role", "collector", "--once"], clock=lambda: 1793613600.0) == 0
    for file in tmp_path.glob("collector.db*"):
        assert b"old-free-collector-marker" not in file.read_bytes()


def test_raw_expiry_uses_the_same_serialized_receipt_as_core(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_sentinel_core.retention import main

    clock = [1792404000.1234563]
    _, events = captured_commands(tmp_path, clock, monkeypatch)
    receipt = datetime.fromisoformat(
        events[0]["received_at"].replace("Z", "+00:00")
    ).timestamp()
    clock[0] = receipt + 1209600
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "collector.db"))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    monkeypatch.setenv("COWRIE_LOG_DIR", str(tmp_path / "logs"))
    assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
    assert (
        events[0]["command"]["text"].encode()
        not in (tmp_path / "logs/cowrie.json").read_bytes()
    )


def test_new_session_and_renamed_tty_keep_their_own_auxiliary_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    journal, events = captured_commands(tmp_path, clock, monkeypatch)
    logs = tmp_path / "logs"
    with (logs / "cowrie.json").open("a") as stream:
        for record in (
            {**CONNECT, "session": "session-2"},
            {
                "eventid": "cowrie.command.input",
                "session": "session-2",
                "timestamp": "2026-10-21T10:00:00Z",
                "input": "new-session-copy-marker",
            },
            {
                "eventid": "cowrie.log.closed",
                "session": "session-2",
                "ttylog": "/var/lib/cowrie/tty/opaque-transcript-hash",
            },
        ):
            stream.write(json.dumps(record) + "\n")
    journal.scan(logs)
    tty = logs / "tty"
    tty.mkdir()
    payload = b"new-session-copy-marker\n"
    (tty / "opaque-transcript-hash").write_bytes(
        struct.pack("<iLiiLL", 3, 0, len(payload), 1, int(clock[0]), 0) + payload
    )
    service = logs / "cowrie.log"
    service.write_text(
        "2026-10-19T10:00:00Z [ssh,session-1,192.0.2.10] CMD: "
        + events[0]["command"]["text"]
        + "\n"
        "2026-10-21T10:00:00Z [ssh,session-2,192.0.2.10] CMD: new-session-copy-marker\n"
    )
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "collector.db"))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    monkeypatch.setenv("COWRIE_LOG_DIR", str(logs))
    assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
    clock[0] = 1793613600.0
    assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
    assert events[0]["command"]["text"] not in service.read_text()
    assert "new-session-copy-marker" in service.read_text()
    assert payload in (tty / "opaque-transcript-hash").read_bytes()


def test_unmanaged_archive_does_not_produce_false_cleanup_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    captured_commands(tmp_path, clock, monkeypatch)
    (tmp_path / "logs/cowrie.json.external.gz").write_bytes(b"unmanaged-archive")
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "collector.db"))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    monkeypatch.setenv("COWRIE_LOG_DIR", str(tmp_path / "logs"))
    assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 1
    assert "retention_cleanup_failed" in caplog.text
    assert not (tmp_path / "retention-heartbeat").exists()


def test_large_tty_frames_and_growing_stdin_are_cleaned_without_truncating_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    captured_commands(tmp_path, clock, monkeypatch)
    tty = tmp_path / "logs/tty"
    tty.mkdir()
    payload = b"large-tty-marker-51" * 5000
    path = tty / "session-1.log"
    header = struct.pack("<iLiiLL", 3, 0, len(payload), 2, 1792404000, 0)
    path.write_bytes(header + payload)
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    stdin = downloads / "stdin-owned-capture"
    stdin.write_bytes(b"initial-stdin-marker")
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "collector.db"))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    monkeypatch.setenv("COWRIE_LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("COWRIE_DOWNLOAD_DIR", str(downloads))
    assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
    with stdin.open("ab") as writer:
        writer.write(b"appended-stdin-marker" * 5000)
        writer.flush()
        clock[0] = 1793613600.0
        assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
        assert path.read_bytes()[:24] == header
        assert b"large-tty-marker-51" not in path.read_bytes()
        assert b"stdin-marker" not in stdin.read_bytes()
        writer.write(b"writer-still-open")
        writer.flush()
    assert stdin.read_bytes().endswith(b"writer-still-open")


def test_incomplete_tty_payload_cannot_outlive_its_session_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    captured_commands(tmp_path, clock, monkeypatch)
    tty = tmp_path / "logs/tty"
    tty.mkdir()
    path = tty / "session-1.log"
    header = struct.pack("<iLiiLL", 3, 0, 1000000, 2, 1792404000, 0)
    path.write_bytes(header + b"unfinished-tty-marker")
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "collector.db"))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    monkeypatch.setenv("COWRIE_LOG_DIR", str(tmp_path / "logs"))
    clock[0] = 1793613600.0
    with path.open("ab") as writer:
        assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
        assert b"unfinished-tty-marker" not in path.read_bytes()
        writer.write(b"late-tty-copy")
        writer.flush()
        assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
        assert b"late-tty-copy" not in path.read_bytes()
    assert path.read_bytes()[:24] == header


def test_metadata_expires_at_first_receipt_thirty_days_through_api_and_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [1792404000.0]
    _, events = captured_commands(tmp_path, clock, monkeypatch)
    core = tmp_path / "core"
    core.mkdir()
    settings = replace(configured(core), clock=lambda: clock[0])
    from ai_sentinel_core.retention import main

    monkeypatch.setenv("CORE_DB_PATH", str(settings.database))
    with TestClient(create_app(settings)) as client:
        receipts = [
            client.post("/internal/events", json=event, headers=AUTH).json()
            for event in events
        ]
        client.post("/login", json={"password": "synthetic-test-password"})
        old_id, fresh_id = (receipt["task_id"] for receipt in receipts)
        original = terminal(client, old_id)
        terminal(client, fresh_id)
        clock[0] = 1794995999.0  # First telemetry receipt + 30 days - one second.
        client.post("/login", json={"password": "synthetic-test-password"})
        before = client.get(f"/api/tasks/{old_id}")
        assert before.status_code == 200
        assert before.json()["analysis"] == original["analysis"]
        clock[0] += 1
        assert main(["--role", "core", "--once"], clock=lambda: clock[0]) == 0
        assert client.get(f"/api/tasks/{old_id}").status_code == 404
        assert client.get(f"/tasks/{old_id}").status_code == 404
        assert (
            f'href="/tasks/{old_id}"'
            not in client.get("/tasks", params={"q": old_id}).text
        )
        assert client.get(f"/api/tasks/{fresh_id}").status_code == 200
        assert (
            client.post("/internal/events", json=events[0], headers=AUTH).status_code
            == 410
        )
        for file in core.iterdir():
            if file.is_file():
                data = file.read_bytes()
                assert old_id.encode() not in data
                assert events[0]["event_id"].encode() not in data
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        assert client.get(f"/api/tasks/{old_id}").status_code == 404
        assert client.get(f"/api/tasks/{fresh_id}").status_code == 200


def test_idle_core_removes_metadata_without_traffic_or_external_maintenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [1792404000.0]
    _, events = captured_commands(tmp_path, clock, monkeypatch)
    core = tmp_path / "core"
    core.mkdir()
    settings = replace(configured(core), clock=lambda: clock[0])
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        task_id = client.post("/internal/events", json=events[0], headers=AUTH).json()[
            "task_id"
        ]
        terminal(client, task_id)
        clock[0] = 1794996000.0
        deadline = time.monotonic() + 4
        while any(
            task_id.encode() in f.read_bytes() for f in core.iterdir() if f.is_file()
        ):
            assert time.monotonic() < deadline, "Idle Core retained expired metadata"
            time.sleep(0.02)
        client.post("/login", json={"password": "synthetic-test-password"})
        assert client.get(f"/api/tasks/{task_id}").status_code == 404
        assert (
            client.post("/internal/events", json=events[0], headers=AUTH).status_code
            == 410
        )


def test_http_enforces_metadata_deadline_even_without_background_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [1792404000.0]
    _, events = captured_commands(tmp_path, clock, monkeypatch)
    settings = replace(configured(tmp_path), clock=lambda: clock[0])
    # No lifespan: admission queues a durable task, maintenance is not running.
    client = TestClient(create_app(settings))
    try:
        task_id = client.post("/internal/events", json=events[0], headers=AUTH).json()[
            "task_id"
        ]
        clock[0] = 1794996000.0
        client.post("/login", json={"password": "synthetic-test-password"})
        assert (
            client.post("/internal/events", json=events[0], headers=AUTH).status_code
            == 410
        )
        assert client.get(f"/api/tasks/{task_id}").status_code == 404
        assert f'href="/tasks/{task_id}"' not in client.get("/tasks").text
    finally:
        client.close()


@pytest.mark.parametrize("view", ["task", "raw"])
def test_late_reader_reply_cannot_recreate_deleted_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, view: str
) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from email.message import Message
    from threading import Event

    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    _, events = captured_commands(tmp_path, clock, monkeypatch)
    entered, release, delay = Event(), Event(), Event()

    def delayed_reader(event: dict[str, Any]) -> str:
        if not delay.is_set():
            return json.dumps(events[0])
        entered.set()
        assert release.wait(5)
        raise HTTPError("http://reader/source", 410, "deleted", Message(), None)

    core = tmp_path / "core"
    core.mkdir()
    settings = replace(
        configured(core), clock=lambda: clock[0], source_reader=delayed_reader
    )
    # Queue before lifespan, avoiding unrelated worker/reader requests.
    client = TestClient(create_app(settings))
    task_id = client.post("/internal/events", json=events[0], headers=AUTH).json()[
        "task_id"
    ]
    # Restart processes the task before the delayed source lookup.
    with TestClient(create_app(settings)) as running, ThreadPoolExecutor() as pool:
        running.post("/login", json={"password": "synthetic-test-password"})
        item = terminal(running, task_id)
        url = (
            f"/api/tasks/{task_id}"
            if view == "task"
            else item["evidence"][0]["raw_url"]
        )
        delay.set()
        request = pool.submit(running.get, url)
        try:
            assert entered.wait(5)
            clock[0] = 1794996000.0
            monkeypatch.setenv("CORE_DB_PATH", str(settings.database))
            assert main(["--role", "core", "--once"], clock=lambda: clock[0]) == 0
        finally:
            release.set()
        assert request.result().status_code == 404
        for file in core.iterdir():
            if file.is_file():
                assert events[0]["event_id"].encode() not in file.read_bytes()
                assert task_id.encode() not in file.read_bytes()
    client.close()


def test_pending_outage_alert_cannot_restore_expired_history_after_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    settings = replace(configured(tmp_path), clock=lambda: clock[0])
    client = TestClient(create_app(settings))
    try:
        client.post("/login", json={"password": "synthetic-test-password"})
        with monkeypatch.context() as fault:

            def unavailable(*args: Any, **kwargs: Any) -> None:
                raise OSError("synthetic storage outage")

            fault.setattr(sqlite3, "connect", unavailable)
            assert client.get("/tasks").status_code == 503
        clock[0] = 1794996000.0
        monkeypatch.setenv("CORE_DB_PATH", str(settings.database))
        assert main(["--role", "core", "--once"], clock=lambda: clock[0]) == 0
        client.post("/login", json={"password": "synthetic-test-password"})
        for file in tmp_path.iterdir():
            if file.is_file():
                assert b"storage_unavailable" not in file.read_bytes()
        page = client.get("/tasks")
        assert page.status_code == 200
        assert "Хранилище Core недоступно" not in page.text
        assert "Нет текущих критических проблем" in page.text
        for file in tmp_path.iterdir():
            if file.is_file():
                assert b"storage_unavailable" not in file.read_bytes()
    finally:
        client.close()


def test_current_disk_failure_remains_visible_without_thirty_day_old_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os
    from types import SimpleNamespace

    clock = [1792404000.0]
    settings = replace(configured(tmp_path), clock=lambda: clock[0])
    monkeypatch.setattr(
        os,
        "statvfs",
        lambda path: SimpleNamespace(
            f_blocks=100, f_bavail=0, f_files=100, f_favail=10
        ),
    )
    client = TestClient(create_app(settings))
    try:
        client.post("/login", json={"password": "synthetic-test-password"})
        assert "Диск заполнен" in client.get("/tasks").text
        clock[0] = 1794996000.0
        client.post("/login", json={"password": "synthetic-test-password"})
        page = client.get("/tasks")
        assert page.status_code == 200
        assert "Критический · Активно" in page.text
        assert page.text.count("Диск заполнен") == 2  # Active state + one history row.
        assert "19.10.2026" not in page.text
        assert "18.11.2026" in page.text
    finally:
        client.close()


def test_late_guard_process_reply_cannot_restore_deleted_task_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess
    import sys

    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    _, events = captured_commands(tmp_path, clock, monkeypatch)
    core = tmp_path / "core"
    core.mkdir()
    entered, release = tmp_path / "entered", tmp_path / "release"
    # A delayed OS-process response at the inference transport boundary.
    # Core's Guard adapter, store, queue and worker remain real.
    program = """import json, pathlib, sys, time
for line in sys.stdin:
    pathlib.Path(sys.argv[1]).touch()
    while not pathlib.Path(sys.argv[2]).exists():
        time.sleep(0.01)
    print(json.dumps({"status":"error","score":None,"threshold":0.999,
        "revision":"8e0fdb567ad0d1ddac0c9c1819b182204db26867",
        "reason_code":"model_unavailable"}), flush=True)
"""
    original_popen = subprocess.Popen

    def delayed_process(args: Any, **kwargs: Any) -> Any:
        assert "ai_sentinel_core.guard_worker" in args
        return original_popen(
            [sys.executable, "-c", program, str(entered), str(release)], **kwargs
        )

    monkeypatch.setattr(subprocess, "Popen", delayed_process)
    settings = replace(
        configured(core), clock=lambda: clock[0], guard_model=tmp_path / "model"
    )
    with TestClient(create_app(settings)) as client:
        client.post("/login", json={"password": "synthetic-test-password"})
        task_id = client.post("/internal/events", json=events[0], headers=AUTH).json()[
            "task_id"
        ]
        try:
            deadline = time.monotonic() + 5
            while not entered.exists():
                assert time.monotonic() < deadline
                time.sleep(0.01)
            clock[0] = 1794996000.0
            monkeypatch.setenv("CORE_DB_PATH", str(settings.database))
            assert main(["--role", "core", "--once"], clock=lambda: clock[0]) == 0
        finally:
            release.touch()
        client.post("/login", json={"password": "synthetic-test-password"})
        assert client.get(f"/api/tasks/{task_id}").status_code == 404
    # Lifespan has awaited the in-flight worker commit.
    for file in core.iterdir():
        if file.is_file():
            assert task_id.encode() not in file.read_bytes()
            assert events[0]["event_id"].encode() not in file.read_bytes()


def test_collector_forgets_expired_delivery_receipts_without_replaying_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    journal, events = captured_commands(tmp_path, clock, monkeypatch)
    old_task = "old-task-receipt-marker-51"
    fresh_task = "fresh-task-receipt-marker-51"
    journal.acknowledge(events[0]["event_id"], old_task)
    journal.acknowledge(events[1]["event_id"], fresh_task)
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(journal.database))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    monkeypatch.setenv("COWRIE_LOG_DIR", str(tmp_path / "logs"))
    clock[0] = 1793613600.0
    assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
    assert main(["--role", "collector", "--once"], clock=lambda: clock[0]) == 0
    clock[0] = 1794996000.0
    assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
    assert main(["--role", "collector", "--once"], clock=lambda: clock[0]) == 0
    status = Journal(
        journal.database, "retention-test", clock=lambda: clock[0]
    ).status()
    assert status["deliveries"] == [
        {"event_id": events[1]["event_id"], "task_id": fresh_task}
    ]
    for path in tmp_path.glob("collector.db*"):
        assert old_task.encode() not in path.read_bytes()
        assert events[0]["event_id"].encode() not in path.read_bytes()
        assert events[0]["raw_record_ref"].encode() not in path.read_bytes()
    # Operational cursor survives history deletion: no replay/new receipt time.
    journal.scan(tmp_path / "logs")
    assert journal.pending() == []
    assert journal.status()["deliveries"] == status["deliveries"]


def test_compressed_raw_rotation_preserves_fresh_offsets_and_original_deadlines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gzip

    from ai_sentinel_core.raw_source import ReaderSettings, create_reader_app
    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    journal, events = captured_commands(tmp_path, clock, monkeypatch)
    logs = tmp_path / "logs"
    raw = logs / "cowrie.json"
    archive = logs / "cowrie.json.1.gz"
    archive.write_bytes(gzip.compress(raw.read_bytes()))
    raw.unlink()
    token = tmp_path / "reader-token"
    token.write_text("synthetic-reader-token")
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(journal.database))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    monkeypatch.setenv("COWRIE_LOG_DIR", str(logs))
    clock[0] = 1793613600.0
    assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
    content = gzip.decompress(archive.read_bytes())
    assert events[0]["command"]["text"].encode() not in content
    assert events[1]["command"]["text"].encode() in content
    with TestClient(
        create_reader_app(
            ReaderSettings(logs, journal.database, token, clock=lambda: clock[0])
        )
    ) as reader:
        auth = {"Authorization": "Bearer synthetic-reader-token"}
        assert (
            reader.post("/internal/record", json=events[0], headers=auth).status_code
            == 410
        )
        fresh = reader.post("/internal/record", json=events[1], headers=auth)
        assert fresh.status_code == 200
        assert events[1]["command"]["text"] in fresh.text
        assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
        clock[0] = 1793700000.0  # Fresh event's own original 14-day deadline.
        assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
        assert events[1]["command"]["text"].encode() not in gzip.decompress(
            archive.read_bytes()
        )
        assert (
            reader.post("/internal/record", json=events[1], headers=auth).status_code
            == 410
        )
    assert journal.status()["deliveries"] == [
        {"event_id": event["event_id"], "task_id": None} for event in events
    ]


def test_compressed_service_and_tty_copies_follow_each_session_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gzip

    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    journal, events = captured_commands(tmp_path, clock, monkeypatch)
    logs = tmp_path / "logs"
    with (logs / "cowrie.json").open("a") as stream:
        stream.write(json.dumps({**CONNECT, "session": "session-2"}) + "\n")
    journal.scan(logs)
    service = logs / "cowrie.log.1.gz"
    service.write_bytes(
        gzip.compress(
            (
                "2026-10-19 [ssh,session-1,192.0.2.10] CMD: "
                + events[0]["command"]["text"]
                + "\n"
                "2026-10-21 [ssh,session-2,192.0.2.10] CMD: fresh-archive-session-51\n"
            ).encode()
        )
    )
    tty = logs / "tty"
    tty.mkdir()
    old_tty, fresh_tty = tty / "session-1.log.gz", tty / "session-2.log.gz"
    old_payload = events[0]["command"]["text"].encode()
    fresh_payload = b"fresh-archive-session-51"
    for path, payload in ((old_tty, old_payload), (fresh_tty, fresh_payload)):
        path.write_bytes(
            gzip.compress(
                struct.pack("<iLiiLL", 3, 0, len(payload), 2, int(clock[0]), 0)
                + payload
            )
        )
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(journal.database))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    monkeypatch.setenv("COWRIE_LOG_DIR", str(logs))
    clock[0] = 1793613600.0
    assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
    assert old_payload not in gzip.decompress(service.read_bytes())
    assert fresh_payload in gzip.decompress(service.read_bytes())
    assert old_payload not in gzip.decompress(old_tty.read_bytes())
    assert fresh_payload in gzip.decompress(fresh_tty.read_bytes())
    # A renamed archive cannot acquire a fresh session lifetime.
    renamed = tty / "opaque-hash.gz"
    fresh_tty.rename(renamed)
    clock[0] = 1793872800.0  # Session 2 receipt + 15 days.
    assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
    assert fresh_payload not in gzip.decompress(renamed.read_bytes())
    assert fresh_payload not in gzip.decompress(service.read_bytes())


def test_unknown_archive_text_is_erased_without_borrowing_a_known_record_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gzip

    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    journal, events = captured_commands(tmp_path, clock, monkeypatch)
    logs = tmp_path / "logs"
    content = (logs / "cowrie.json").read_bytes()
    original = events[1]["command"]["text"].encode()
    unknown = b"Z" * len(original)
    archive = logs / "cowrie.json.external.gz"
    archive.write_bytes(gzip.compress(content.replace(original, unknown)))
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(journal.database))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    monkeypatch.setenv("COWRIE_LOG_DIR", str(logs))
    assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
    cleaned = gzip.decompress(archive.read_bytes())
    assert unknown not in cleaned
    assert events[0]["command"]["text"].encode() in cleaned
    assert original in (logs / "cowrie.json").read_bytes()
    assert len(journal.pending()) == 2


@pytest.mark.parametrize("keep_plain", [False, True])
@pytest.mark.parametrize(
    "phase", ["output_fsync", "overwrite", "replace_before", "replace_after"]
)
def test_compressed_cleanup_recovers_interruption_without_leaving_old_copies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str, keep_plain: bool
) -> None:
    import gzip
    import os

    from ai_sentinel_core.raw_source import ReaderSettings, create_reader_app
    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    journal, events = captured_commands(tmp_path, clock, monkeypatch)
    logs = tmp_path / "logs"
    raw = logs / "cowrie.json"
    archive = logs / "cowrie.json.1.gz"
    archive.write_bytes(gzip.compress(raw.read_bytes()))
    if not keep_plain:
        raw.unlink()
    info = archive.stat()
    token = tmp_path / "reader-token"
    token.write_text("synthetic-reader-token")
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(journal.database))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    monkeypatch.setenv("COWRIE_LOG_DIR", str(logs))
    clock[0] = 1793613600.0
    original_replace, original_write, original_sync = os.replace, os.pwrite, os.fsync
    injected = False

    def fail_sync(fd: int) -> None:
        nonlocal injected
        if (
            not injected
            and phase == "output_fsync"
            and any(
                p.stat().st_ino == os.fstat(fd).st_ino
                for p in logs.glob(".retention-*")
            )
        ):
            injected = True
            raise OSError("synthetic output fsync failure")
        original_sync(fd)

    def fail_write(fd: int, data: bytes, offset: int) -> int:
        nonlocal injected
        if not injected and phase == "overwrite" and os.fstat(fd).st_ino == info.st_ino:
            injected = True
            original_write(fd, data[: max(1, len(data) // 2)], offset)
            raise OSError("synthetic interrupted erasure")
        return original_write(fd, data, offset)

    def fail_replace(source: Any, destination: Any) -> None:
        nonlocal injected
        if (
            not injected
            and phase.startswith("replace")
            and Path(destination) == archive
        ):
            injected = True
            if phase == "replace_after":
                original_replace(source, destination)
            raise OSError("synthetic interrupted replacement")
        original_replace(source, destination)

    with archive.open("rb") as previous_inode:
        with monkeypatch.context() as fault:
            fault.setattr(os, "fsync", fail_sync)
            fault.setattr(os, "pwrite", fail_write)
            fault.setattr(os, "replace", fail_replace)
            assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 1
        assert injected
        assert not (tmp_path / "retention-heartbeat").exists()
        with TestClient(
            create_reader_app(
                ReaderSettings(logs, journal.database, token, clock=lambda: clock[0])
            )
        ) as reader:
            auth = {"Authorization": "Bearer synthetic-reader-token"}
            assert (
                reader.post(
                    "/internal/record", json=events[0], headers=auth
                ).status_code
                == 503
            )
            assert reader.post(
                "/internal/record", json=events[1], headers=auth
            ).status_code == (200 if keep_plain else 503)
            assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
            assert (
                reader.post(
                    "/internal/record", json=events[0], headers=auth
                ).status_code
                == 410
            )
            assert (
                reader.post(
                    "/internal/record", json=events[1], headers=auth
                ).status_code
                == 200
            )
        previous_inode.seek(0)
        assert previous_inode.read() == b"\0" * info.st_size
    assert not list(logs.glob(".retention-*"))
    copies = [gzip.decompress(archive.read_bytes())]
    if keep_plain:
        copies.append(raw.read_bytes())
    for content in copies:
        assert events[0]["command"]["text"].encode() not in content
        assert events[1]["command"]["text"].encode() in content


@pytest.mark.parametrize("phase", ["building", "ready"])
def test_renamed_archive_after_failed_build_does_not_orphan_an_expiring_temporary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    import gzip
    import os

    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    journal, events = captured_commands(tmp_path, clock, monkeypatch)
    logs = tmp_path / "logs"
    archive = logs / "cowrie.json.1.gz"
    archive.write_bytes(gzip.compress((logs / "cowrie.json").read_bytes()))
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(journal.database))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    monkeypatch.setenv("COWRIE_LOG_DIR", str(logs))
    original_sync, original_replace = os.fsync, os.replace

    def fail_output_sync(fd: int) -> None:
        if phase == "building" and any(
            p.stat().st_ino == os.fstat(fd).st_ino for p in logs.glob(".retention-*")
        ):
            raise OSError("synthetic interrupted build")
        original_sync(fd)

    def fail_replace(source: Any, destination: Any) -> None:
        original_replace(source, destination)
        if phase == "ready":
            raise OSError("synthetic interruption after replacement")

    clock[0] = 1793613600.0
    with monkeypatch.context() as fault:
        fault.setattr(os, "fsync", fail_output_sync)
        fault.setattr(os, "replace", fail_replace)
        assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 1
    if phase == "building":
        assert list(logs.glob(".retention-*"))
    archive.rename(logs / "cowrie.json.2.gz")
    clock[0] = 1793700000.0
    assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
    assert not list(logs.glob(".retention-*"))
    assert events[1]["command"]["text"].encode() not in gzip.decompress(
        (logs / "cowrie.json.2.gz").read_bytes()
    )


def test_gzip_header_text_is_not_kept_outside_record_retention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gzip

    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    journal, events = captured_commands(tmp_path, clock, monkeypatch)
    logs = tmp_path / "logs"
    archive = logs / "cowrie.json.1.gz"
    header = "header-copy-unknown-deadline-51"
    with (
        archive.open("wb") as physical,
        gzip.GzipFile(filename=header, mode="wb", fileobj=physical) as compressed,
    ):
        compressed.write((logs / "cowrie.json").read_bytes())
    assert header.encode() in archive.read_bytes()
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(journal.database))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    monkeypatch.setenv("COWRIE_LOG_DIR", str(logs))
    assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
    assert header.encode() not in archive.read_bytes()
    assert events[1]["command"]["text"].encode() in gzip.decompress(
        archive.read_bytes()
    )


def test_valid_gzip_with_unknown_partial_tail_erases_tail_and_keeps_fresh_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gzip

    from ai_sentinel_core.retention import main

    clock = [1792404000.0]
    journal, events = captured_commands(tmp_path, clock, monkeypatch)
    logs = tmp_path / "logs"
    archive = logs / "cowrie.json.1.gz"
    tail = b'{"input":"unknown-partial-tail-51'
    content = (logs / "cowrie.json").read_bytes() + tail
    archive.write_bytes(gzip.compress(content))
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(journal.database))
    monkeypatch.setenv("COWRIE_SENSOR_ID", "retention-test")
    monkeypatch.setenv("COWRIE_LOG_DIR", str(logs))
    assert main(["--role", "raw", "--once"], clock=lambda: clock[0]) == 0
    cleaned = gzip.decompress(archive.read_bytes())
    assert b"unknown-partial-tail-51" not in cleaned
    assert len(cleaned) == len(content)
    assert events[1]["command"]["text"].encode() in cleaned
