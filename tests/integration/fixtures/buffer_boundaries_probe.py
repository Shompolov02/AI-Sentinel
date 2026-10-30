"""Observe hysteresis and disk/chunk admission through the loopback health API."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any
from urllib.request import urlopen

from ai_sentinel_core.collector import run


async def probe() -> None:
    depth = 0

    def health() -> dict[str, Any]:
        with urlopen("http://127.0.0.1:8090/health", timeout=2) as reply:
            return dict(json.load(reply))

    async def until(mode: str) -> dict[str, Any]:
        for _ in range(200):
            await asyncio.sleep(0.05)
            if task.done():
                await task
            try:
                status = await asyncio.to_thread(health)
            except OSError:
                continue
            if status["intake"] == mode:
                return status
        raise AssertionError(f"Collector never reached {mode}")

    def send(event: dict[str, Any]) -> dict[str, str]:
        raise AssertionError("No source records in capacity-only scenario")

    task = asyncio.create_task(run(sender=send, capacity=lambda: depth))
    try:
        await until("normal")
        depth = 800
        assert (await until("slowed"))["scan_interval_seconds"] == 10
        depth = 799
        await asyncio.sleep(2.5)
        assert (await asyncio.to_thread(health))["intake"] == "slowed"
        depth = 1000
        await until("stopped")
        depth = 601
        await asyncio.sleep(2.5)
        assert (await asyncio.to_thread(health))["intake"] == "stopped"
        depth = 600
        await until("normal")
        # Real filesystem consumption, not a mock of the admission controller.
        filler = Path("/data/reserve-test")
        filler.write_bytes(b"x" * (16 * 1024**2))
        assert (await until("stopped"))["disk_low"] is True
        filler.unlink()
        await until("normal")
        # Account for a physical file occupying the chunk directory, including
        # a pending maximum-size chunk reservation before accepting another batch.
        chunk = Path("/data/chunks/reservation-test")
        chunk.write_bytes(b"x" * (3 * 1024**2))
        await until("stopped")
        chunk.unlink()
        await until("normal")
        print("Core 80/100/60 hysteresis, disk reserve and chunks verified", flush=True)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


logging.basicConfig(level=logging.INFO)
asyncio.run(probe())
