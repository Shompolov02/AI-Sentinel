# Phase 1 runtime isolation

Status: accepted for Issue #27.

## Context

The earlier four-service Compose topology put Nginx and Target App on a
non-internal `prod_net`. That bridge gave the intentionally vulnerable Target
App an outbound route. Making the bridge internal without changing ingress
would prevent reliable host port publication on the supported Docker Desktop
runtime, as already observed for Cowrie in the TCP ingress decision.

## Decision

`deploy/docker-compose.yml` now has five services and five non-overlapping
IPv4 networks. Target App joins only `prod_net`; Cowrie joins only `honeynet`.
Both networks are `internal: true` with the isolated IPv4 gateway mode, so
neither workload has a default route or a bridge gateway to the host. The
HTTP Nginx service joins `prod_net` and the internal `http_edge` network.
It has no published port. A dedicated, non-root `http-ingress` service joins
`http_edge` and the host-facing `http_ingress` network and publishes only
`${BIND_ADDRESS:-127.0.0.1}:${HTTP_PORT:-8080}`. The existing Cowrie TCP
ingress remains on `honeynet` and `cowrie_ingress`; the two ingress paths do
not share a network.

The HTTP ingress is an Nginx stream proxy to `nginx:8080`. It sends PROXY
protocol so the main Nginx preserves the peer address observed by ingress.
Docker Desktop may show its host gateway address for a loopback connection
because of NAT; this address is not a client-supplied forwarding header. The main
Nginx accepts that address only from `HTTP_EDGE_SUBNET`; Target App has no
attachment to this trust network. It still overwrites client forwarding
headers and `X-Request-ID`, enforces Host policy, and writes the JSON access
log. A separate loopback-only listener on port 8081 checks `/health` without
requiring a PROXY header. All services have healthchecks and the ingress
services depend on healthy upstreams.

## Verification and limits

The Compose policy checks the exact service and network attachments, isolated
gateway mode, non-root users, published ports, mounts, resources, and other
security controls. `make test-runtime` probes DNS, TCP and route tables from
the actual Target App and Cowrie containers in both directions. It also
checks host and external routes without relying on a public endpoint, plus
the three host-facing protocols and persistent named volumes after service
recreation. Every negative network probe is bounded by two seconds. A missing
Docker Engine is a failure for this acceptance command.

The host-facing ingress containers necessarily use non-internal networks;
the deny-egress acceptance scope is the deliberately vulnerable Target App
and Cowrie. This decision supersedes the older four-service, three-network
topology stated in the Phase 1 interview notes and the Issue #25 ingress ADR.
