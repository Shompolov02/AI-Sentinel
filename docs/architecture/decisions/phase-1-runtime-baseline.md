# Phase 1 Runtime Baseline

Status: accepted for Issue #19.

This decision records the baseline runtime contracts for the local Honeynet
environment. It does not declare the deliberately vulnerable Target App to be a
production service.

## Canonical deployment configuration

`deploy/docker-compose.yml` is the canonical Compose manifest for the Phase 1
runtime. Validation and runtime tooling must use this file; the initial manifest
defines the isolated `prod_net` and `honeynet` networks.
Issue #25 adds a dedicated TCP ingress bridge while keeping Cowrie only on
`honeynet`; see [Cowrie TCP ingress](phase-1-cowrie-ingress.md).

Cowrie uses the immutable image reference
`cowrie/cowrie:3.0.15@sha256:fc57120d88c2bfb5817f63f6c132ce5c2969b641c2f1ac67887652b6f294148d`.
Do not replace it with a floating tag.

## HTTP ingress and health

Nginx rejects requests with an unknown `Host` using status `444`. `GET /health`
is proxied to Target App so the response reflects upstream availability rather
than masking its failure with a local proxy response.

## Error and request correlation contracts

Target App HTTP errors use the common JSON shape:

```json
{
  "error": "Request could not be processed",
  "correlation_id": "<server-generated-id>",
  "status": 400
}
```

Nginx overwrites inbound `X-Request-ID` with its own `$request_id` before
proxying. In the Compose deployment, Target App accepts that 32-character hex
ID from the edge and uses it in response headers, supported response bodies,
and structured logs. Nginx also writes the same ID to its JSON access log.
Direct Target App runs generate their own IDs, so direct clients cannot choose
one. Compose admits only Nginx and Target App to `prod_net`; adding another
service to that network changes the request-ID trust boundary and requires
review. Client-supplied forwarding headers are overwritten or removed at Nginx.

## Runtime test harness

Runtime checks are implemented with Pytest and the Docker CLI/Compose plugin for
the local environment. Tests should identify an unavailable Docker Engine or
CLI explicitly rather than silently treating runtime assertions as passed.
