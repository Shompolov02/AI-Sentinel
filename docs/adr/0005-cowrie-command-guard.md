# Cowrie commands: experimental local ML Guard and honest Fallback (#48)

The owner selected viavoice/mdeberta-ru-prompt-injection on 2026-10-23 after
reviewing local offline measurements, explicitly retaining its limitations for
the diploma research. The operating threshold is 0.999, the configuration in
that review. This is an experimental detector, not a claimed security guarantee.
The semantic ML option was chosen over a signature-only Guard. No additional
regex layer is introduced in this slice; the broader target architecture does
not imply that all future layers already exist. CONTEXT.md records this scope.
The agreed seams are Core intake -> authenticated task API/page, and real Cowrie
commands -> normalizer -> Fluent Bit -> TLS -> the same page.

Pin revision 8e0fdb567ad0d1ddac0c9c1819b182204db26867 and verify ONNX and tokenizer
SHA-256 before loading. Run ONNX Runtime on CPU inside Core, with local read-only
weights. No weights or ML caches enter Git, Docker build context or macOS Python.
The optional Guard overlay gives Core 2 CPU / 3 GiB (the measured trial ceiling);
normal login-only deployment stays small. Core remains in core_management only.
Load once on first command in a persistent child process inside the Core
container. Private JSON pipes carry only command text and the structured result.
This prevents native initialization/inference from holding the HTTP process GIL;
worker failure produces an error instead of a Low. No shell is involved. Inspect the complete command with 256-token windows,
64-token overlap and max-score aggregation; do not silently truncate input.

The public v1 contract adds event_type=command / cowrie.command.input and
command={text}, mutually exclusive with login. Text is bounded by the existing
64-KiB record/intake limits; no shell command is executed by the analyzer. The
collector uses input from Cowrie and the existing connect provenance, source
reference and UUIDv5 identity. Passwords are still excluded. Malformed commands
are quarantined with reference/length/digest only. No command is copied into
ordinary logs, audit reasons or verdicts.

Guard results contain status (blocked/no_match/error), score (null on error),
threshold, model ID, revision, rules/version, window count and a safe reason code.
A blocked current command yields High / Fallback with Evidence. A no-match means
only that this classifier did not detect an injection: there is no LLM client in
this slice, and no other command severity rules were approved. Such a task is
failed (unable to assess), without a severity or fabricated verdict. Guard errors
also fail closed. A no-match uses insufficient_rules; an unavailable Guard uses
guard_unavailable. Both cases retain Fallback, Guard outcome, reason, unknown MITRE,
Evidence and a local operator warning. No external inference call exists.

Task analysis is persisted separately so failed tasks can expose their analysis
without pretending to have a verdict. Replay and restart retain the original
result and append-only audit. Historical login verdicts are not reclassified.
Command text persists in Cowrie raw logs, collector outbox/chunks and the Core
event payload; it is not copied into verdicts, Evidence or audit. Evidence uses
safe facts and a source reference. Raw-source retrieval belongs to #49 and
coordinated 14/30-day deletion to #51. This change does not complete retention. Use synthetic commands
only until the retention slice is accepted. Previous-command context belongs to
the later LLM slice; no previous command or external request is assembled here.

Trial: 40 runs / 39 unique manually labelled examples. At 0.999, 17/18 injection
examples were detected and 3/21 non-injection examples were false positives.
The phrase requesting a safe classification regardless of content was missed.
Peak process RSS was about 2107 MiB; startup varied 30-93 seconds, short examples
about 0.1-1 seconds, a 13-window command about 49 seconds. These observations are
not representative accuracy estimates, calibrated probabilities or SLOs.
Higher thresholds traded false positives for more misses. No extra rules are
silently added to hide these experimental results.
