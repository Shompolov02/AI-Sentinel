"""Local maintenance entry point; it never accepts filesystem deletion paths."""

from __future__ import annotations

import argparse
import logging
import os
import sqlite3
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from .aux_retention import clean_auxiliary
from .buffer_retention import maintain_collector
from .raw_retention import clean_raw
from .store import Store
from .telemetry import Journal


def main(
    argv: Sequence[str] | None = None, *, clock: Callable[[], float] = time.time
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("core", "collector", "raw"), required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    os.umask(0o077)
    while True:
        try:
            if args.role == "core":
                database = Path(os.environ["CORE_DB_PATH"])
                store = Store(database, clock=clock)
                store.expire_text(clock())
                store.expire_metadata(clock())
            else:
                database = Path(
                    os.environ.get("COLLECTOR_DB_PATH", "/data/collector.db")
                )
                journal = Journal(database, os.environ["COWRIE_SENSOR_ID"], clock=clock)
                if args.role == "raw":
                    logs = Path(os.environ.get("COWRIE_LOG_DIR", "/cowrie-logs"))
                    journal.scan(logs)
                    clean_auxiliary(
                        journal,
                        logs,
                        Path(os.environ["COWRIE_DOWNLOAD_DIR"])
                        if "COWRIE_DOWNLOAD_DIR" in os.environ
                        else None,
                        clock(),
                        tty_directory=Path(os.environ["COWRIE_TTY_DIR"])
                        if "COWRIE_TTY_DIR" in os.environ
                        else None,
                    )
                    clean_raw(journal, logs, clock())
                    journal.expire_metadata(clock())
                else:
                    maintain_collector(journal, clock())
            if args.role == "raw":
                (database.parent / "retention-heartbeat").write_text(str(time.time()))
            if args.once:
                return 0
        except (OSError, sqlite3.Error, KeyError, ValueError):
            logging.getLogger("ai_sentinel_retention").critical(
                "retention_cleanup_failed"
            )
            if args.once:
                return 1
        time.sleep(1)


if __name__ == "__main__":
    raise SystemExit(main())
