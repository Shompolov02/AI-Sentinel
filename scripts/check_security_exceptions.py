"""Fail closed when a Security Exception is incomplete or expired."""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

REQUIRED_FIELDS = (
    "finding_id",
    "secops_owner",
    "justification",
    "scope",
    "compensating_control",
    "expires_on",
    "follow_up",
)


def _read_fields(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key.strip()] = value.strip().strip('"')
    return fields


def check(path: Path, today: dt.date) -> list[str]:
    errors: list[str] = []
    fields = _read_fields(path)
    missing = [field for field in REQUIRED_FIELDS if not fields.get(field)]
    if missing:
        errors.append(f"{path}: missing required fields: {', '.join(missing)}")
    expires_on = fields.get("expires_on")
    if expires_on:
        try:
            expiry = dt.date.fromisoformat(expires_on)
        except ValueError:
            errors.append(f"{path}: expires_on must be YYYY-MM-DD")
        else:
            if expiry < today:
                errors.append(f"{path}: expired on {expiry.isoformat()}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--today", type=dt.date.fromisoformat, default=dt.date.today())
    args = parser.parse_args()

    files = [
        candidate
        for path in args.paths
        for candidate in (sorted(path.glob("*.yaml")) if path.is_dir() else [path])
    ]
    errors = [error for path in files for error in check(path, args.today)]
    if errors:
        print("Security Exception gate failed:", file=sys.stderr)
        print("\n".join(errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
