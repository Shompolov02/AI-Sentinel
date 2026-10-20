"""Public synthetic data for Core API and runtime acceptance."""

from typing import Any

EVENT: dict[str, Any] = {
    "schema_version": 1,
    "event_id": "5697880a-7ac4-43db-bfe9-1692ee3cefc7",
    "occurred_at": "2026-10-20T10:00:00Z",
    "received_at": "2026-10-20T10:00:01Z",
    "event_type": "login_attempt",
    "cowrie_event_type": "cowrie.login.failed",
    "sensor_id": "cowrie-lab",
    "session_id": "synthetic-session-1",
    "source_ip": "192.0.2.10",
    "source_port": 41000,
    "protocol": "ssh",
    "destination_port": 2222,
    "raw_record_ref": "synthetic:login-1",
    "login": {"username": "synthetic", "outcome": "failure", "password_length": 12},
}

TEST_VERIFIER = (
    "scrypt$30313233343536373839616263646566$"
    "0705f89cdc458b71f286308f95163098d7853dce0233ca88e283c0e67815f9bebc314"
    "df30e43f30fb34a2a1bfd1eb4d0eb496c67b766c02922149b5678e8daef"
)
