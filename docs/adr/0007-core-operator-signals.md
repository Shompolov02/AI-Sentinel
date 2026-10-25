# Core operator signals and emergency page (#50)

Accepted by the owner on 2026-10-25: show the latest 100 historical signals and
current critical problems, with time, level, safe reason and task link when one
exists. Operational signals describe Core availability/analysis failures; their
warning/critical levels are independent of a Cowrie event's threat severity.
The exact catalogue is in the v1 contract. No quantitative SLO or low-disk
threshold is introduced.

Reuse existing immutable task audit for Fallback and analysis-error warnings.
Persist critical episodes and their resolution in an additive `core_alerts`
table in the existing SQLite volume. Repeated observations of one unresolved
cause/task share an episode; resolution preserves history. A state-write error
stays active until that task reaches a terminal state. The single Core process
retains pending episodes in memory when SQLite cannot accept them, flushing on
successful HTTP activity or orderly shutdown. Abrupt process loss before flush
can lose that history: local container logs remain the failure evidence. This
chooses the existing storage boundary over a new independent monitoring service.
Retention for this table joins #51; rollback leaves the additive table intact.

When the database cannot authorize/read the page, Core returns a generic 503
without task data. When Core itself is down, the existing page ingress returns
the same safe message for its own 502/504 upstream failures. It reports only
unavailability, never an inferred disk failure. No Docker socket, broad log
reader, new public monitoring API or administrative action is introduced.
Collector-only signals remain in its local logs, as required by #44.

Public HTTP/page, browser and real-container test seams were confirmed by the
owner. Failure checks include actual SQLite locking, a controlled ENOSPC at
the storage boundary, queue saturation and a real page proxy with Core stopped
and restored. None of these assign production availability/latency targets.
