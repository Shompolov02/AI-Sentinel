"""AC2 at a full buffer: real Fluent Bit, Core HTTP and controlled first receipt."""

import asyncio
import json
import logging
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import HTTPCookieProcessor, Request, build_opener, urlopen

import uvicorn

from ai_sentinel_core.app import Settings, create_app
from ai_sentinel_core.auth import hash_password
from ai_sentinel_core.collector import run


async def probe() -> None:
    first = 1793145600.0
    now = [first]
    accepting = False
    delivered: dict[str, str] = {}
    notices: list[logging.LogRecord] = []
    cleanup_failures: list[logging.LogRecord] = []
    fail_cleanup = len(sys.argv) > 1 and sys.argv[1] == "expiry_fault"
    fail_log = len(sys.argv) > 1 and sys.argv[1] == "expiry_logfault"
    log_available = not fail_log
    old = (
        "expired-command-marker-52",
        "expired-failed-login-52",
        "expired-success-login-52",
    )
    fresh = [f"fresh-expiry-marker-{index}-52" for index in range(6)]
    state = Path("/tmp/expiry-core")  # noqa: S108 - private test-container tmpfs
    state.mkdir()
    token = state / "token"
    token.write_text("synthetic-expiry-token")
    password = state / "password"
    password.write_text(hash_password("synthetic-expiry-password"))
    core = uvicorn.Server(
        uvicorn.Config(
            create_app(
                Settings(state / "core.db", token, password, clock=lambda: now[0])
            ),
            host="127.0.0.1",
            port=8091,
            access_log=False,
        )
    )
    core_task = asyncio.create_task(core.serve())
    opener = build_opener(HTTPCookieProcessor())

    def request(path: str, payload: dict[str, Any] | None = None) -> bytes:
        request = Request(
            "http://127.0.0.1:8091" + path,
            data=json.dumps(payload).encode() if payload is not None else None,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer synthetic-expiry-token",
            },
        )
        with opener.open(request, timeout=3) as response:
            return bytes(response.read())

    def page() -> str:
        request("/login", {"password": "synthetic-expiry-password"})
        return request("/tasks").decode()

    def send(event: dict[str, Any]) -> dict[str, str]:
        if not accepting:
            raise URLError("synthetic Core outage")
        receipt: dict[str, str] = json.loads(request("/internal/events", event))
        delivered[event["event_id"]] = receipt["task_id"]
        return receipt

    def health() -> dict[str, Any]:
        with urlopen("http://127.0.0.1:8090/health", timeout=3) as response:
            return dict(json.load(response))

    def contains(root: Path, marker: str) -> bool:
        for path in root.rglob("*"):
            try:
                if path.is_file() and marker.encode() in path.read_bytes():
                    return True
            except FileNotFoundError:
                continue
        return False

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            nonlocal log_available
            if "buffer_event_expired" in record.getMessage():
                if not log_available:
                    log_available = True
                    raise OSError("synthetic expiry log unavailable")
                notices.append(record)
            if "retention_cleanup_failed" in record.getMessage():
                cleanup_failures.append(record)

    handler = Capture()
    logger = logging.getLogger("ai_sentinel_telemetry")
    logger.addHandler(handler)
    source = Path("/cowrie-logs/cowrie.json")
    source.write_text(
        json.dumps(
            {
                "eventid": "cowrie.session.connect",
                "session": "expiry-session",
                "src_ip": "192.0.2.52",
                "src_port": 41000,
                "dst_port": 2222,
                "protocol": "ssh",
            }
        )
        + "\n"
    )

    def append(kind: str, marker: str, padding: int = 0) -> None:
        record = {
            "eventid": kind,
            "session": "expiry-session",
            "timestamp": "2026-09-01T00:00:00Z",
        }
        if kind == "cowrie.command.input":
            record["input"] = marker + "x" * padding
        else:
            record.update(
                {"username": marker, "password": "synthetic-raw-only-password"}
            )
        with source.open("a") as stream:
            stream.write(json.dumps(record) + "\n")

    append("cowrie.command.input", old[0], 3500)
    append("cowrie.login.failed", old[1])
    append("cowrie.login.success", old[2])
    task = asyncio.create_task(run(clock=lambda: now[0], sender=send))

    async def until(predicate: Callable[[], bool], timeout: float = 40) -> None:
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            if task.done():
                await task
                raise AssertionError("Collector exited during expiry")
            if await asyncio.to_thread(predicate):
                return
            await asyncio.sleep(0.05)
        raise AssertionError("Expiry condition did not become observable")

    handles = []
    try:
        await until(
            lambda: all(contains(Path("/data/chunks"), marker) for marker in old)
        )
        now[0] = first + 86400
        for marker in fresh:
            append("cowrie.command.input", marker, 500)
        await until(lambda: health()["intake"] == "stopped")
        assert 8000 <= (await asyncio.to_thread(health))["outbox_bytes"] <= 10000
        assert contains(Path("/data"), fresh[0])
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        task = asyncio.create_task(run(clock=lambda: now[0], sender=send))
        now[0] = first + 14 * 86400 - 1
        await until(
            lambda: all(contains(Path("/data/chunks"), marker) for marker in old)
        )
        assert not notices
        before = await asyncio.to_thread(page)
        assert "Принятых задач пока нет" in before and "Сигналов пока нет" in before
        for path in Path("/data/chunks").rglob("*"):
            if path.is_file() and old[0].encode() in path.read_bytes():
                handles.append(path.open("rb"))
        assert handles
        blocked = Path("/data/chunks/blocked-cleanup")
        if fail_cleanup:
            blocked.write_text(old[0])
            blocked.chmod(0)
        now[0] = first + 14 * 86400
        if fail_cleanup or fail_log:
            deadline = asyncio.get_running_loop().time() + 15
            while not task.done():
                assert asyncio.get_running_loop().time() < deadline
                await asyncio.sleep(0.05)
            try:
                await task
            except OSError as error:
                if fail_cleanup:
                    assert isinstance(error, PermissionError)
                else:
                    assert "synthetic expiry log unavailable" in str(error)
            else:
                raise AssertionError("Physical cleanup failure was hidden")
            if fail_cleanup:
                assert cleanup_failures and cleanup_failures[-1].levelname == "CRITICAL"
                assert blocked.exists()
                blocked.chmod(0o600)
                assert old[0] in blocked.read_text()
            else:
                assert not notices
            task = asyncio.create_task(run(clock=lambda: now[0], sender=send))
        await until(
            lambda: (
                len(notices) == 3
                and not any(contains(Path("/data"), marker) for marker in old)
                and contains(Path("/data/chunks"), fresh[0])
            )
        )
        assert all(record.levelname == "CRITICAL" for record in notices)
        assert len({record.getMessage() for record in notices}) == 3
        assert all(
            "task_id" not in record.getMessage()
            and not any(marker in record.getMessage() for marker in old + tuple(fresh))
            for record in notices
        )
        for handle in handles:
            content = handle.read()
            assert not any(marker.encode() in content for marker in old)
        after = await asyncio.to_thread(page)
        assert "Принятых задач пока нет" in after and "Сигналов пока нет" in after
        assert not delivered
        now[0] += 1
        accepting = True
        await until(lambda: len(delivered) == 6)
        assert len(set(delivered.values())) == 6
        assert len(notices) == 3
        assert not any(contains(state, marker) for marker in old)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        task = asyncio.create_task(run(clock=lambda: now[0], sender=send))
        await asyncio.sleep(2)
        assert len(notices) == 3 and len(delivered) == 6
        print(
            "Full buffer: 14d-1 / 14d / 14d+1, 3 local critical losses, 6 fresh tasks",
            flush=True,
        )
    finally:
        for handle in handles:
            handle.close()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        core.should_exit = True
        await core_task
        logger.removeHandler(handler)


logging.basicConfig(level=logging.INFO)
asyncio.run(probe())
