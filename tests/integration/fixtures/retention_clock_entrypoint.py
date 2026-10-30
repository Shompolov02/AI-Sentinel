"""Test-only shared clock; mounted read-only, never exposed by production HTTP."""

import asyncio
import logging
import os
import sys
from pathlib import Path

import uvicorn

from ai_sentinel_core.app import Settings, create_app
from ai_sentinel_core.collector import run
from ai_sentinel_core.raw_source import ReaderSettings, create_reader_app, tls_reader
from ai_sentinel_core.retention import main


def clock() -> float:
    return float(Path("/test-clock/now").read_text())


role = sys.argv[1]
if role == "collector":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run(clock=clock))
elif role == "retention":
    raise SystemExit(main(["--role", "raw"], clock=clock))
elif role == "reader":
    app = create_reader_app(
        ReaderSettings(
            Path("/cowrie-logs"),
            Path("/registry/collector.db"),
            Path("/run/secrets/raw-reader-tokens"),
            clock=clock,
        )
    )
    uvicorn.run(
        app,
        host="0.0.0.0",  # noqa: S104 - isolated Compose service, no host port
        port=8443,
        access_log=False,
        ssl_keyfile="/run/secrets/raw-reader.key",
        ssl_certfile="/run/secrets/raw-reader.crt",
    )
else:
    assert role == "core"
    app = create_app(
        Settings(
            Path(os.environ["CORE_DB_PATH"]),
            Path(os.environ["CORE_TOKENS_FILE"]),
            Path(os.environ["CORE_PASSWORD_HASH_FILE"]),
            clock=clock,
            guard_model=Path(os.environ["CORE_GUARD_MODEL_DIR"])
            if os.environ.get("CORE_GUARD_MODEL_DIR")
            else None,
            source_reader=tls_reader(
                Path(os.environ["CORE_RAW_READER_TOKENS_FILE"]),
                Path(os.environ["CORE_RAW_READER_CA_FILE"]),
            ),
        )
    )
    uvicorn.run(
        app,
        host="0.0.0.0",  # noqa: S104 - isolated Compose service, no host port
        port=8000,
        access_log=False,
    )
