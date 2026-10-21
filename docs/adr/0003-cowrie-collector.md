# Cowrie collection before Fluent Bit disk buffering

Accepted by the owner on 2026-10-21 for #46, child of #44.

The agreed test seams are the normalizer's public interface followed by Core's
HTTP API/read-only page, and real SSH/Telnet through the combined Compose stand.
Tests advance one observable behavior at a time (red before green).

Fluent Bit receives stdin from a fixed Python input adapter. It reads the Cowrie
volume read-only, whitelists login fields and emits normalized JSON before Fluent Bit
creates filesystem chunks. No attacker-controlled text is used as a command.
An ordinary raw tail input with filesystem buffering would copy passwords.
The adapter has a durable SQLite outbox: it commits the normalized event and
cursor together, re-emitting unacknowledged events. A loopback-only delivery
adapter forwards Fluent Bit batches to Core using verified TLS and a collector
token, then acknowledges the outbox. A crash at any boundary can duplicate
delivery, but cannot acknowledge a lost event. Core remains authoritative for
task ID and analysis deduplication.

A file generation is a persisted random UUID associated with device/inode and
the digest of its first complete line (a bounded prefix for oversized lines). Rename rotation preserves generation;
truncation or a changed first line starts a new generation. UUIDv5 over sensor,
generation and byte offset identifies a record. received_at is fixed on first
normalization and stored in the outbox. raw_record_ref contains sensor,
generation and byte offset; a local file registry resolves generation to the
last observed filename. Copying logs to another inode is a new source, not a
replay; preserve the collector volume when restarting or moving the collector.
Content-only IDs were rejected because separate identical records at different
positions must remain separate events; a fresh ID on each read would instead
duplicate analysis on replay.

Session-connect records persist source IP/port, destination port and protocol;
login records are correlated by configured sensor and Cowrie session. Missing
required provenance is quarantined, never guessed. Login timestamp is the event
time; first normalization is reception time. Password length counts Unicode
characters. Username stays local; password text is neither persisted nor emitted.
Other Cowrie record types are ignored until their slices are implemented.

Malformed records stay in the original local log; quarantine stores only opaque
reference, reason, length and digest, with a warning in the collector log.
There is no duplicate raw payload in quarantine, SQLite, Fluent Bit chunks or
container logs. Login attempts never call an LLM. Successful logins create failed
(unable to assess) tasks with an explicit pending-policy reason, without a Low
verdict; their High severity and burst counting belong to #47.

The collector belongs only to core_ingest, publishes no host ports and mounts no
Docker socket. Cowrie remains only in honeynet. Existing Core TLS/token rotation
applies to the collector. Loss of collector state loses stable source identities;
preserve its named volume. Retention, buffer sizing/expiry and overload policy
remain assigned to #51/#52; this slice does not claim to complete them.
