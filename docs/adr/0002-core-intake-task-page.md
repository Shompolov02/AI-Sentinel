# Core intake, durable tasks and read-only SecOps page

Accepted by the owner on 2026-10-20 for #45, child of #44. Public HTTP/API,
rendered pages and a real Compose/TLS/restart/isolation scenario are the agreed
test seams. Tests advance one observable behavior at a time.

Core owns one SQLite database on `core-data`: accepted events, tasks, verdicts,
Evidence, append-only audit entries and opaque server-side sessions. A committed
queued event precedes the HTTP acknowledgement; an asyncio.Queue dispatches a
maximum of 1000 unfinished tasks, with recovery of unfinished work on restart.
Full intake returns 503 without accepting an event. A duplicate ID and identical
payload returns its existing task; changed content under that ID returns 409.

`POST /internal/events` requires TLS and a collector Bearer token. The event is
strict version 1 JSON: UUID event_id, timezone-aware occurred_at/received_at,
login_attempt event_type, cowrie.login.failed cowrie_event_type, sensor_id,
session_id, source_ip/source_port, ssh or telnet protocol, destination_port,
opaque raw_record_ref, and login {username, outcome: failure, password_length}.
Unknown fields (including passwords and command text) are rejected. UUID task_id
also serves as correlation_id. The 202 response includes these IDs and queued
state; repeated delivery reports the existing state. States are queued,
processing, completed and failed, displayed in Russian. Other types are rejected
until their corresponding slices (#46 onward); Low is never a catch-all verdict.

The isolated failed-login slice yields Low, a reason, Rules analysis method,
rules_version, not_applicable guard_result, unknown MITRE mapping and Evidence
IDs. Evidence records structured failure facts and an opaque source reference;
synthetic sources are labelled and are never fetched as paths/URLs. Audit entries
record timestamp, action, actor, task/correlation ID and structured details.
Admission, transitions, verdict and successful SecOps login are audited.

The read-only page uses /login, /tasks and /tasks/{task_id}; authenticated
GET /api/tasks/{task_id} exposes task history, verdict, Evidence and task audit.
The existing single-owner laboratory password is entered locally using getpass;
only a salted scrypt verifier is stored. Random session cookies are HttpOnly,
SameSite=Strict and expire server-side after 30 idle minutes. HTTP for the page
is the previously accepted lab limitation, so Secure cookies cannot be required.
Service tokens and human sessions are separate authorities.

Core ingestion, management and host-facing page ingress use separate networks:
172.30.60.0/24, 172.30.70.0/24 and 172.30.80.0/24, checked for conflicts before
runtime. TLS intake listens on 8443 without a published host port; the separate
page ingress publishes 8082 with mandatory CORE_BIND_ADDRESS, independent of
honeypot port settings. Cowrie remains only in honeynet. A local CA issues the
intake certificate; collectors verify the CA and DNS name. Certificate renewal
and 256-bit service-token rotation are manual runbook operations; two tokens may
be temporarily accepted during rotation. Nginx terminates TLS at the ingestion
boundary; its private HTTP upstream is confined to core_management. The page
proxy exposes only page routes and cannot forward /internal routes.

The optional Core Compose overlay extends the canonical Phase 1 manifest. This
keeps the existing five-service Phase 1 verification usable before credentials
are provisioned, while the Core runtime suite checks the combined topology.
The normalizer's stable event-ID construction, full login severity policy,
command handling, raw-source retrieval, and retention jobs belong to later
slices; no raw passwords or commands are accepted or stored by this slice.
