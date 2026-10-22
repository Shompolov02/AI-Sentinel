# Cowrie login severity and the event-time window (#47)

Accepted by the owner on 2026-10-22 for #47, child of #44. The owner selected
Cowrie event time (`occurred_at`), and confirmed the test seams: Cowrie records
through the real normalizer, Core HTTP API and read-only page with controlled
time; plus the real Fluent Bit/TLS runtime path.

For a newly accepted failure at time T, count unique accepted failures for the
same canonical source IP in the inclusive interval [T - 300 seconds, T]. Count
the current failure. SSH/Telnet, sessions and sensors share the IP counter;
source ports do not split it. The first four failures yield Low; count >= 5
yields Medium. Successful login always yields High, never Critical, and neither
increments nor resets the failure counter. Login analysis uses Rules only,
without an LLM or Prompt Guard. MITRE mapping remains unknown.

Only records already accepted when this event is admitted are available for its
assessment. Later arrivals never revisit old verdicts. Out-of-order records
exclude already accepted records whose event times are later than T. A late
record can affect a subsequently admitted record if it is in that record's
window. Collector `received_at`, Core admission time and worker time do not
select the window. No clock-skew tolerance or timestamp rewriting is added.

Core atomically stores a count snapshot with each new task in SQLite, before
returning 202. A repeated event returns the original task before counting;
content conflicts and rejected events do not change the count. An index over
IP, failure flag and event time supports the window query. Snapshots survive
queue delay, shutdown and recovery. Rules version is `cowrie-login-v2`.
Evidence records outcome, protocol, original Cowrie type, failure_count,
window_seconds=300, window_basis=occurred_at and window_end; the reason explains
the threshold. Existing source references and secret minimization are preserved.

On upgrading an existing Core volume, build observations from accepted tasks in
original admission order, in a single transaction. Do not rewrite completed or
failed tasks, their verdicts, Evidence or audit. In particular, a successful
login previously marked unable to assess remains that historical result;
only pending/new tasks use the new policy. The additive table is ignored by
older code, permitting rollback with the same volume. Keep it with task history;
coordinated retention belongs to #51, not this change.

Tests observe task IDs, verdicts, Evidence, audit and HTML via public interfaces,
not SQLite internals. Controlled event times cover the threshold, exact window
boundary, expiry, unrelated IPs, out-of-order delivery, replay and restart,
including a stopped worker. The runtime harness appends synthetic Cowrie JSON
records with controlled timestamps to the real Cowrie log, in addition to real
SSH/Telnet logins, and observes all three levels through Fluent Bit/TLS and the
SecOps page. Existing network-isolation and password-free buffer checks remain.
