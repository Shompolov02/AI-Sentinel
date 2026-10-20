"""Supervise Fluent Bit and feed only sanitized, durable events to its stdin."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path

import uvicorn

from .delivery import create_delivery_app, tls_sender
from .telemetry import Journal

logger = logging.getLogger("ai_sentinel_telemetry")


async def run() -> None:
    os.umask(0o077)
    state = Path("/data")
    (state / "chunks").mkdir(exist_ok=True)
    journal = Journal(state / "collector.db", os.environ["COWRIE_SENSOR_ID"])
    sender = tls_sender(
        Path("/run/secrets/collector-tokens"), Path("/run/secrets/ca.crt")
    )
    application = create_delivery_app(journal, sender)
    server = uvicorn.Server(
        uvicorn.Config(
            application,
            host="127.0.0.1",
            port=8090,
            access_log=False,
        )
    )
    process = await asyncio.create_subprocess_exec(
        "/fluent-bit/bin/fluent-bit",
        "-c",
        "/etc/collector/fluent-bit.conf",
        stdin=asyncio.subprocess.PIPE,
    )

    async def pump() -> None:
        if process.stdin is None:
            raise RuntimeError("Fluent Bit stdin unavailable")
        while process.returncode is None:
            await asyncio.to_thread(journal.scan, Path("/cowrie-logs"))
            for event in await asyncio.to_thread(journal.pending):
                process.stdin.write((json.dumps(event) + "\n").encode())
                await process.stdin.drain()
            (state / "heartbeat").write_text(str(time.time()))
            await asyncio.sleep(2)

    web = asyncio.create_task(server.serve())
    input_task = asyncio.create_task(pump())
    fluent = asyncio.create_task(process.wait())
    try:
        done, _ = await asyncio.wait(
            (web, input_task, fluent),
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in done:
            task.result()
        if fluent in done:
            raise RuntimeError("Fluent Bit exited")
    finally:
        server.should_exit = True
        input_task.cancel()
        await asyncio.gather(input_task, return_exceptions=True)
        if process.returncode is None:
            process.terminate()
        await asyncio.gather(fluent, web, return_exceptions=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(run())
    except Exception:
        logger.critical("collector_stopped intake_unavailable=true")
        raise SystemExit(1) from None
