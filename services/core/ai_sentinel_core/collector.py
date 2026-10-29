"""Supervise Fluent Bit and feed only sanitized, durable events to its stdin."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

import uvicorn

from .backpressure import CHUNK_RESERVE, Pressure
from .buffer_retention import buffer_gate, buffer_owner, erase_chunks, requested_cutoff
from .delivery import Sender, create_delivery_app, tls_capacity, tls_sender
from .storage import text_expired
from .telemetry import Journal

logger = logging.getLogger("ai_sentinel_telemetry")


class BufferProcess:
    def __init__(
        self, journal: Journal, clock: Callable[[], float], pressure: Pressure
    ) -> None:
        self.journal = journal
        self.clock = clock
        self.process: subprocess.Popen[bytes] | None = None
        self.pressure = pressure
        self.inflight: set[str] = set()
        self.writing = b""

    def stop(self, *, reset: bool = False) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            if reset:
                # A graceful shutdown may unlink chunks before we can scrub
                # their inodes. Unacknowledged input is durable in the outbox.
                self.process.kill()
            else:
                self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        if self.process.stdin is not None:
            self.process.stdin.close()
        self.process = None

    def reset(self, cutoff: float) -> None:
        try:
            self.stop(reset=True)
            erase_chunks(self.journal, cutoff)
        except (OSError, sqlite3.Error):
            logger.critical("retention_cleanup_failed")
            raise
        self.inflight.clear()
        self.writing = b""

    def cycle(self) -> None:
        with buffer_gate(self.journal.database.parent):
            self.journal.expire_text(self.clock())
            self.journal.expire_metadata(self.clock())
            cutoff = requested_cutoff(self.journal)
            if self.process is not None and self.process.poll() is not None:
                raise RuntimeError(f"Fluent Bit exited ({self.process.returncode})")
            if cutoff is not None:
                self.reset(cutoff)
            if self.process is None:
                # The durable outbox is authoritative. Rebuild old chunks before
                # replay so a supervisor restart cannot accumulate duplicates.
                self.reset(self.clock())
                self.process = subprocess.Popen(  # noqa: S603
                    [
                        "/fluent-bit/bin/fluent-bit",
                        "-c",
                        "/etc/collector/fluent-bit.conf",
                    ],
                    stdin=subprocess.PIPE,
                    bufsize=0,
                )
                if self.process.stdin is not None:
                    os.set_blocking(self.process.stdin.fileno(), False)
            if self.process.stdin is None:
                raise RuntimeError("Fluent Bit stdin unavailable")
            if not self.writing:
                self.inflight = self.journal.awaiting(self.inflight)
                status = self.pressure.snapshot()
                if (
                    status["chunk_bytes"] + CHUNK_RESERVE > self.pressure.chunk_limit
                    or status["disk_low"]
                ):
                    return
                for event in self.journal.pending():
                    if event["event_id"] in self.inflight:
                        continue
                    if text_expired(event, self.clock()):
                        continue
                    packet = (
                        json.dumps(event, ensure_ascii=False, separators=(",", ":"))
                        + "\n"
                    ).encode()
                    if self.writing and len(self.writing) + len(packet) > 65537:
                        break
                    self.writing += packet
                    self.inflight.add(event["event_id"])
            if self.writing:
                try:
                    written = os.write(self.process.stdin.fileno(), self.writing)
                except BlockingIOError:
                    return
                self.writing = self.writing[written:]


async def run(
    *,
    clock: Callable[[], float] = time.time,
    sender: Sender | None = None,
    capacity: Callable[[], int] | None = None,
) -> None:
    os.umask(0o077)
    state = Path("/data")
    (state / "chunks").mkdir(exist_ok=True)
    journal = Journal(
        state / "collector.db", os.environ["COWRIE_SENSOR_ID"], clock=clock
    )
    if sender is None:
        capacity = capacity or tls_capacity(
            Path("/run/secrets/collector-tokens"), Path("/run/secrets/ca.crt")
        )
    sender = sender or tls_sender(
        Path("/run/secrets/collector-tokens"), Path("/run/secrets/ca.crt")
    )
    pressure = Pressure(journal)
    server = uvicorn.Server(
        uvicorn.Config(
            create_delivery_app(journal, sender, pressure=pressure),
            host="127.0.0.1",
            port=8090,
            access_log=False,
        )
    )
    child = BufferProcess(journal, clock, pressure)

    async def action(function: Callable[[], None]) -> None:
        work = asyncio.create_task(asyncio.to_thread(function))
        try:
            await asyncio.shield(work)
        except asyncio.CancelledError:
            await work
            raise

    async def scan() -> None:
        while True:
            status = await asyncio.to_thread(pressure.snapshot)
            if status["intake"] != "stopped":
                await action(lambda: journal.scan(Path("/cowrie-logs")))
            status = await asyncio.to_thread(pressure.snapshot)
            # Wake promptly after delivery/cleanup frees space, while a slowed
            # source is scanned only once per ten seconds.
            for _ in range(status["scan_interval_seconds"] * 5):
                await asyncio.sleep(0.2)
                current = await asyncio.to_thread(pressure.snapshot)
                if current["intake"] != status["intake"]:
                    break

    async def pump() -> None:
        while True:
            await action(child.cycle)
            (state / "heartbeat").write_text(str(time.time()))
            await asyncio.sleep(1)

    async def observe_core() -> None:
        while True:
            if capacity is not None:
                try:
                    depth = await asyncio.to_thread(capacity)
                    await asyncio.to_thread(pressure.core_depth, depth)
                except (OSError, ValueError, KeyError, IndexError):
                    # Delivery reports the outage; keep the last known pressure.
                    pass
            await asyncio.sleep(2)

    with buffer_owner(state) as owns_child:
        if not owns_child:
            raise RuntimeError("Collector buffer already supervised")
        web = asyncio.create_task(server.serve())
        input_task = asyncio.create_task(scan())
        output_task = asyncio.create_task(pump())
        capacity_task = asyncio.create_task(observe_core())
        try:
            done, _ = await asyncio.wait(
                (web, input_task, output_task, capacity_task),
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in done:
                task.result()
        finally:
            server.should_exit = True
            input_task.cancel()
            output_task.cancel()
            capacity_task.cancel()
            await asyncio.gather(
                input_task, output_task, capacity_task, return_exceptions=True
            )
            await asyncio.to_thread(child.stop)
            await web


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(run())
    except Exception:
        logger.critical("collector_stopped intake_unavailable=true")
        raise SystemExit(1) from None
