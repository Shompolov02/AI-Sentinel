"""Real supervisor and Fluent Bit; controlled Core transport, isolated volumes."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen
from uuid import NAMESPACE_URL, uuid5

from ai_sentinel_core.collector import run


async def probe() -> None:
    accepting = False
    delivered: set[str] = set()
    observed: dict[str, tuple[str, str]] = {}

    def send(event: dict[str, Any]) -> dict[str, str]:
        identity = (event["received_at"], event["raw_record_ref"])
        assert observed.setdefault(event["event_id"], identity) == identity
        if not accepting:
            raise URLError("synthetic Core outage")
        delivered.add(event["event_id"])
        return {"task_id": str(uuid5(NAMESPACE_URL, event["event_id"]))}

    def health() -> dict[str, Any]:
        with urlopen("http://127.0.0.1:8090/health", timeout=2) as reply:
            return dict(json.load(reply))

    source = Path("/cowrie-logs/cowrie.json")
    source.write_text(
        json.dumps(
            {
                "eventid": "cowrie.session.connect",
                "session": "pressure",
                "src_ip": "192.0.2.52",
                "src_port": 41000,
                "dst_port": 2222,
                "protocol": "ssh",
            }
        )
        + "\n"
    )
    with source.open("a") as stream:
        for index in range(40):
            stream.write(
                json.dumps(
                    {
                        "eventid": "cowrie.command.input",
                        "timestamp": "2026-10-28T00:00:00Z",
                        "session": "pressure",
                        "input": f"marker-{index:02d}-" + "x" * 1000,
                    }
                )
                + "\n"
            )

    task = asyncio.create_task(run(sender=send))
    try:
        for _ in range(800):
            await asyncio.sleep(0.05)
            if task.done():
                await task
            try:
                status = await asyncio.to_thread(health)
            except OSError:
                continue
            if status["intake"] == "stopped":
                break
        else:
            raise AssertionError("Collector did not stop at its outbox budget")
        assert 8000 <= status["outbox_bytes"] <= 10000, status
        assert status["scan_interval_seconds"] == 10
        snapshot = status["outbox_bytes"]
        await asyncio.sleep(3)
        status = await asyncio.to_thread(health)
        assert status["outbox_bytes"] == snapshot
        assert (
            sum(
                p.stat().st_size for p in Path("/data/chunks").rglob("*") if p.is_file()
            )
            <= 4 * 1024 * 1024
        )
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        task = asyncio.create_task(run(sender=send))
        await asyncio.sleep(2)
        status = await asyncio.to_thread(health)
        assert status["intake"] == "stopped"
        assert status["outbox_bytes"] == snapshot
        accepting = True
        for _ in range(1200):
            await asyncio.sleep(0.05)
            if task.done():
                await task
            if len(delivered) == 40:
                break
        assert len(delivered) == 40, len(delivered)
        status = await asyncio.to_thread(health)
        assert status["intake"] == "normal", status
        assert status["outbox_bytes"] == 0
        print("Pressure stop/resume: all 40 unique records delivered", flush=True)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


logging.basicConfig(level=logging.INFO)
asyncio.run(probe())
