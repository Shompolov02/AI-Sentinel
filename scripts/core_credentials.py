"""Provision local Core credentials; never accepts a password on the command line."""

from __future__ import annotations

import argparse
import getpass
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/core"))
from ai_sentinel_core.auth import hash_password


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    if directory.exists():
        parser.error("Use a new directory; existing credentials are never overwritten")
    password = getpass.getpass("Existing laboratory password: ")
    confirmation = getpass.getpass("Repeat password: ")
    if not password or password != confirmation:
        parser.error("Passwords must be non-empty and match")
    directory.mkdir(parents=True, mode=0o700)
    directory.chmod(0o700)
    for name, value in (
        ("password-hash", hash_password(password)),
        ("collector-tokens", secrets.token_urlsafe(32)),
    ):
        path = directory / name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(value + "\n")
        # Individual read-only bind mounts must be readable by container UIDs.
        # The host directory itself is 0700 and is never mounted as a directory.
        path.chmod(0o644)
    print(f"Created credential files under {directory}; password was not stored.")


if __name__ == "__main__":
    main()
