# Phase 1 Runtime Baseline

Status: accepted for Issue #19.

This decision records the baseline runtime contracts for the local Honeynet
environment. It does not declare the deliberately vulnerable Target App to be a
production service.

## Canonical deployment configuration

`deploy/docker-compose.yml` is the canonical Compose manifest for the Phase 1
runtime. Validation and runtime tooling must use this file; the initial manifest
defines the isolated `prod_net` and `honeynet` networks.

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

Nginx overwrites inbound `X-Request-ID` before proxying. The request ID used by
the application is returned in the `X-Request-ID` response header, including
for errors and health responses. Client-supplied IDs are not trusted.

## Runtime test harness

Runtime checks are implemented with Pytest and the Docker CLI/Compose plugin for
the local environment. Tests should identify an unavailable Docker Engine or
CLI explicitly rather than silently treating runtime assertions as passed.