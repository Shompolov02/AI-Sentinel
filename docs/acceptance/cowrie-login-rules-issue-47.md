# Acceptance evidence — Cowrie login rules (#47)

Base: `ea2d0ed` (merged collector #57). Branch: `codex/issue-47-cowrie-rules`.
Owner confirmed on 2026-10-22: event-time (`occurred_at`) window and the public
normalizer → Core HTTP API/read-only page seams, plus Fluent Bit/TLS runtime.
See ADR 0004 for boundary and late-delivery semantics.

| Acceptance criterion | Evidence |
| --- | --- |
| First four failures Low, fifth onward Medium, common IP across SSH/Telnet/sessions | `test_fifth_failure_counts_ssh_telnet_and_sessions_without_rewriting_history`; runtime controlled records from the real Cowrie log through Fluent Bit/TLS |
| Success High, previous verdicts unchanged, no Critical from login alone | `test_successful_cowrie_login_has_high_verdict_on_secops_page`; replay/restart and unchanged API task assertions; rules produce only Low/Medium/High |
| Controlled time from Cowrie record to visible verdict for all three cases | `tests/unit/test_login_rules.py` exercises real Journal, HTTP API and HTML; `test_core_runtime.py` appends controlled Cowrie records and observes four Low, boundary Medium, expired-window Low and success High |

TDD red → green observed:

- Success: old code returned failed; implementation returns completed/High.
- Fifth failure: old rule returned Low; new rule returns Medium.
- Success Evidence on the rendered page: old text incorrectly said failure;
  corrected page reports successful login.

Additional checks cover exact 300-second inclusion, expiry at 300.001 seconds,
other IPv4/IPv6 sources, future event exclusion for late arrivals, buffered
records separated in event time, unchanged task/Evidence/audit on replay,
restart with persistent counts, success not counting/resetting failures, and
queue recovery using each event's admission snapshot.

Upgrade verification used an isolated copy of Core from base `ea2d0ed` and its
public HTTP API to create four Low tasks and one successful-login failed task.
The new Core opened the same database: all five public task responses remained
identical, including Evidence and audit; the next failure returned Medium with
failure_count=5. No private database assertions were used.

The original untracked `GLOSSARY.md`, `docs/adr/0001-first-agent-core-slice.md`
and `docs/spec/ai-agent-core-integrations.md` were preserved byte-for-byte and
are excluded from the change. No real credentials were used in acceptance.
