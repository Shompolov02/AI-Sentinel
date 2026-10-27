"""Real collector supervisor/Fluent Bit, blocked TLS delivery and a trusted clock."""

import asyncio
import gzip
import json
import os
import time
from collections.abc import Callable
from pathlib import Path

from ai_sentinel_core.collector import run
from ai_sentinel_core.retention import main
from ai_sentinel_core.telemetry import Journal


async def probe() -> None:
    now = [float(int(time.time()))]
    first = now[0]
    source = Path("/input/cowrie.json")
    connect = {
        "eventid": "cowrie.session.connect",
        "session": "retention-live",
        "src_ip": "192.0.2.51",
        "src_port": 41000,
        "dst_port": 2222,
        "protocol": "ssh",
    }
    source.write_text(json.dumps(connect) + "\n")

    def append(text: str) -> None:
        with source.open("a") as stream:
            stream.write(
                json.dumps(
                    {
                        "eventid": "cowrie.command.input",
                        "timestamp": "2026-10-26T00:00:00Z",
                        "session": connect["session"],
                        "input": text,
                    }
                )
                + "\n"
            )

    def chunk_contains(marker: bytes) -> bool:
        return any(
            marker in p.read_bytes()
            for p in Path("/data/chunks").rglob("*")
            if p.is_file()
        )

    async def until(predicate: Callable[[], bool]) -> None:
        # A bounded condition wait; no real fourteen-day wait or fake subprocess.
        for _ in range(300):
            if task.done():
                await task
                raise AssertionError("Collector exited during buffer maintenance")
            if predicate():
                return
            await asyncio.sleep(0.05)
        raise AssertionError("Real buffer did not reach expected state")

    task = asyncio.create_task(run(clock=lambda: now[0]))
    try:
        append("expired-live-buffer-marker-51")
        await until(lambda: chunk_contains(b"expired-live-buffer-marker-51"))
        now[0] += 86400
        append("fresh-live-buffer-marker-51")
        await until(lambda: chunk_contains(b"fresh-live-buffer-marker-51"))
        archive = source.parent / "cowrie.json.1.gz"
        archive.write_bytes(gzip.compress(source.read_bytes()))
        now[0] = first + 14 * 86400
        result = await asyncio.to_thread(
            main, ["--role", "collector", "--once"], clock=lambda: now[0]
        )
        assert result == 0
        assert not chunk_contains(b"expired-live-buffer-marker-51")
        for file in Path("/data").rglob("*"):
            if file.is_file():
                assert b"expired-live-buffer-marker-51" not in file.read_bytes(), file
        await until(lambda: chunk_contains(b"fresh-live-buffer-marker-51"))
        journal = Journal(
            Path("/data/collector.db"), "retention-live", clock=lambda: now[0]
        )
        assert [event["command"]["text"] for event in journal.pending()] == [
            "fresh-live-buffer-marker-51"
        ]
        os.environ["COWRIE_LOG_DIR"] = "/input"
        assert (
            await asyncio.to_thread(
                main, ["--role", "raw", "--once"], clock=lambda: now[0]
            )
            == 0
        )
        compressed = gzip.decompress(archive.read_bytes())
        assert b"expired-live-buffer-marker-51" not in compressed
        assert b"fresh-live-buffer-marker-51" in compressed
        assert b"expired-live-buffer-marker-51" not in source.read_bytes()
        assert not list(source.parent.glob(".retention-*"))
        print("Gzip and plain source cleaned while collector runs", flush=True)
        print("Live chunks erased; fresh outbox replayed", flush=True)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


asyncio.run(probe())
