# Active Security Exceptions

Only approved, time-bounded exceptions belong in this directory, one YAML file
per exception. The file must contain `finding_id`, `justification`, `scope`, a
SecOps `secops_owner`, `compensating_control`, `expires_on`, and `follow_up`.

`make security-exceptions` fails for missing fields, malformed dates, and dates
before today. The quality gate runs this check, so an expired exception cannot
continue to suppress a security finding. Approval requires an independent
review from SecOps and a linked remediation follow-up.