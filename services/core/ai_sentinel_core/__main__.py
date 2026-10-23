from __future__ import annotations

import os
from pathlib import Path

from .app import Settings, create_app


def application() -> object:
    settings = Settings(
        Path(os.environ["CORE_DB_PATH"]),
        Path(os.environ["CORE_TOKENS_FILE"]),
        Path(os.environ["CORE_PASSWORD_HASH_FILE"]),
        guard_model=Path(os.environ["CORE_GUARD_MODEL_DIR"])
        if os.environ.get("CORE_GUARD_MODEL_DIR")
        else None,
    )
    if not settings.password_hash.read_text().strip().startswith("scrypt$"):
        raise ValueError("A scrypt password verifier is required")
    tokens = settings.tokens.read_text().splitlines()
    if not 1 <= len(tokens) <= 2 or any(len(token) < 32 for token in tokens):
        raise ValueError(
            "One or two collector tokens of at least 32 characters are required"
        )
    os.umask(0o077)
    return create_app(settings)
