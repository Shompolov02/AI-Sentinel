"""Supervise Fluent Bit and feed only sanitized, durable events to its stdin."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

import uvicorn

from .buffer_retention import buffer_owner, erase_chunks, requested_cutoff
from .delivery import create_delivery_app, tls_sender
from .storage import file_gate, text_expired
from .telemetry import Journal

logger = logging.getLogger("ai_sentinel_telemetry")


class BufferProcess:
    def __init__(self, journal: Journal, clock: Callable[[], float]) -> None:
        self.journal = journal
        self.clock = clock
        self.process: subprocess.Popen[bytes] | None = None

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        if self.process.stdin is not None:
            self.process.stdin.close()
        self.process = None

    def cycle(self) -> None:
        with file_gate(self.journal.database.parent / "buffer"):
            self.journal.expire_text(self.clock())
            cutoff = requested_cutoff(self.journal)
            if self.process is not None and self.process.poll() is not None:
                raise RuntimeError(f"Fluent Bit exited ({self.process.returncode})")
            if cutoff is not None:
                self.stop()
                erase_chunks(self.journal, cutoff)
            if self.process is None:
                self.process = subprocess.Popen(  # noqa: S603
                    [
                        "/fluent-bit/bin/fluent-bit",
                        "-c",
                        "/etc/collector/fluent-bit.conf",
                    ],
                    stdin=subprocess.PIPE,
                )
            if self.process.stdin is None:
                raise RuntimeError("Fluent Bit stdin unavailable")
            for event in self.journal.pending():
                if not text_expired(event, self.clock()):
                    self.process.stdin.write(
                        (json.dumps(event, ensure_ascii=False) + "\n").encode()
                    )
            self.process.stdin.flush()


async def run(*, clock: Callable[[], float] = time.time) -> None:
    os.umask(0o077)
    state = Path("/data")
    (state / "chunks").mkdir(exist_ok=True)
    journal = Journal(
        state / "collector.db", os.environ["COWRIE_SENSOR_ID"], clock=clock
    )
    sender = tls_sender(
        Path("/run/secrets/collector-tokens"), Path("/run/secrets/ca.crt")
    )
    server = uvicorn.Server(
        uvicorn.Config(
            create_delivery_app(journal, sender),
            host="127.0.0.1",
            port=8090,
            access_log=False,
        )
    )
    child = BufferProcess(journal, clock)

    async def action(function: Callable[[], None]) -> None:
        work = asyncio.create_task(asyncio.to_thread(function))
        try:
            await asyncio.shield(work)
        except asyncio.CancelledError:
            await work
            raise

    async def scan() -> None:
        while True:
            await action(lambda: journal.scan(Path("/cowrie-logs")))
            await asyncio.sleep(2)

    async def pump() -> None:
        while True:
            await action(child.cycle)
            (state / "heartbeat").write_text(str(time.time()))
            await asyncio.sleep(1)

    with buffer_owner(state) as owns_child:
        if not owns_child:
            raise RuntimeError("Collector buffer already supervised")
        web = asyncio.create_task(server.serve())
        input_task = asyncio.create_task(scan())
        output_task = asyncio.create_task(pump())
        try:
            done, _ = await asyncio.wait(
                (web, input_task, output_task), return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                task.result()
        finally:
            server.should_exit = True
            input_task.cancel()
            output_task.cancel()
            await asyncio.gather(input_task, output_task, return_exceptions=True)
            await asyncio.to_thread(child.stop)
            await web


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(run())
    except Exception:
        logger.critical("collector_stopped intake_unavailable=true")
        raise SystemExit(1) from None
