# Security reporting

Report suspected vulnerabilities privately to the repository SecOps owner; do
not publish exploit details, credentials, or sensitive telemetry in a public
issue. Include affected component/version, reproduction or evidence, impact,
and a safe contact path. SecOps triages the report, records the finding/rule,
and coordinates remediation.

If remediation cannot land immediately, use the Security Exception issue
template and an approved YAML record under `docs/security/exceptions/`. Every
exception is scoped, owned by SecOps, has a compensating control, follow-up,
and an expiry. `make security-exceptions` is fail-closed for expired records.