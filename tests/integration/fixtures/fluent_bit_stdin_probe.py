"""Exercise production Fluent Bit config with two records in one open-pipe write."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path


def main() -> None:
    payload = sys.stdin.buffer.read()
    event_ids = [json.loads(line)["event_id"].encode() for line in payload.splitlines()]
    state = Path("/data")
    (state / "chunks").mkdir()
    config = state / "probe.conf"
    config.write_text(
        Path("/etc/collector/fluent-bit.conf")
        .read_text()
        .replace("Log_Level warn", "Log_Level info")
    )
    log = state / "probe.log"
    with log.open("w") as output:
        process = subprocess.Popen(  # noqa: S603
            ["/fluent-bit/bin/fluent-bit", "-c", str(config)],
            stdin=subprocess.PIPE,
            stdout=output,
            stderr=output,
        )
        try:
            assert process.stdin is not None
            deadline = time.monotonic() + 15
            while "[input:stdin:" not in log.read_text():
                assert process.poll() is None, log.read_text()
                assert time.monotonic() < deadline, log.read_text()
                time.sleep(0.05)
            # One write is the real bug trigger: a pipe does not preserve the
            # producer's individual record boundaries for the consumer's read.
            process.stdin.write(payload)
            process.stdin.flush()
            deadline = time.monotonic() + 5
            while True:
                chunks = b"".join(p.read_bytes() for p in state.rglob("*.flb"))
                if all(event_id in chunks for event_id in event_ids):
                    break
                assert time.monotonic() < deadline, (
                    "Both records must reach filesystem chunks with stdin open\n"
                    + log.read_text()
                )
                time.sleep(0.05)
            assert process.poll() is None
            print("Both records persisted with stdin open")
        finally:
            process.terminate()
            if process.stdin is not None:
                process.stdin.close()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
