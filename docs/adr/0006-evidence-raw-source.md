# Evidence and a dedicated read-only Cowrie source reader (#49)

Decisions confirmed by the owner on 2026-10-24; parent specification #44.
Implementation is proceeding in slices: this document records the agreed design,
not acceptance of all #49 criteria.

A separate raw-reader service mounts cowrie-logs and the collector registry
read-only. It joins only core_management, has no published port, and accepts
requests from Core over CA/name-verified TLS with a separate reader service token.
Cowrie and collector retain their existing network memberships. Raw records are
not copied into Core SQLite, normalized delivery buffers, verdicts or audit.

Core resolves a task and its Evidence server-side; the browser cannot supply a
path, URL, offset or arbitrary source reference. The reader resolves the opaque
reference using the collector registry, checks sensor, generation, file identity,
line boundary and the record's correspondence to the accepted event. The reader
returns one original UTF-8 JSON line as text/plain, never the whole log file.
The original password is present only when explicitly opening its raw login line.

Evidence includes a fragment of up to 512 Unicode characters. Commands may contain
an attacker-supplied token, as permitted by the first-scenario ADR. Login fragments
use only event type, protocol and username; passwords are excluded. Truncation is
labelled. The source link expands inside its task card; browser code inserts the
response with textContent. Raw content is absent from the task list and is not
embedded in the initial page. Synthetic events have no real raw source.

The first user remains SecOps. Source access permits SecOps, DevOps and Auditor;
other authenticated roles receive 403 and missing/expired sessions receive 401.
The same gate protects task API, cards and list so a denied role cannot read
Evidence through an alternate response. Human sessions and collector/reader
service tokens are separate authorities. All Core and reader responses retain
no-store, including errors. Explicit reads renew the 30-minute idle session;
polling does not. Actual additional users remain deferred until a second person
needs access; no account-management endpoint is added.

The application factory's trusted operator_role configuration defaults to SecOps.
The production entrypoint always uses that default and exposes no environment or
HTTP override. Role-policy tests configure a single synthetic operator per app.
At login the server-assigned role is stored alongside the opaque session digest
in an additive session_roles table and recorded in the login audit. Requests do
not choose their role; restarting with different operator configuration does not
change existing sessions. Pre-#49 sessions migrate as the original sole SecOps,
retaining their inactivity timestamp; role metadata expires with the session.

Unless deletion was already confirmed, source availability is checked on each
authorized task API/card read, before
issuing a live source link and fragment. This deliberately adds a bounded reader
request (3-second timeout, one limited raw line) rather than caching a status that
could present a deleted source as available. The validation text is discarded;
only an explicit source-link response exposes raw JSON to the browser.

Evidence source_status distinguishes available, deleted, unavailable and synthetic.
Only available supplies a source link and excerpt. A known registered source
confirmed absent from a readable directory yields reader/Core 410 and the card's
«Источник удалён». Core also projects command.text=null and removes the fragment
from the response; it does not rewrite stored events, analysis or task audit.
The browser handles deletion between card loading and clicking by removing the
old link, excerpt and displayed command. A fresh page shows the same state.

Core retains positive deletion proof (event ID and first confirmation time) in
an additive source_deletions table. It contains no command or raw text. Once
confirmed, deleted remains known across Core/reader restarts, reader outages and
disabling the optional overlay. The source endpoint continues returning 410
without contacting the reader. An unavailable probe never creates this marker.
Coordinated removal of the marker with task metadata belongs to #51.

The reader searches by registered file identity among up to 1000 cowrie.json*
names, so a rename can resolve before the collector updates the registry. A
missing registry/directory, unknown generation, replacement, symlink or possible
gzip archive does not prove deletion. These yield unavailable, not deleted, and
can recover on a later read. No filesystem path or exception text is exposed.
Coordinated 14/30-day deletion remains #51; that slice must retain deletion proof
if it removes the source registry too. Current presentation is not a claim of
physical erasure from Core SQLite or other command copies.

Agreed TDD seams: normalized events through Core intake and authenticated task
HTTP/page, plus real Cowrie through collector/Fluent Bit/TLS to the same card.
Scenarios include inert HTML/scripts, correct record selection, authorization,
expiry, no-store, rotation/replacement, deletion and transient reader failure.
