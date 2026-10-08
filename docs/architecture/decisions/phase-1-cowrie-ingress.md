# Phase 1 Cowrie TCP ingress

Status: accepted for Issue #25.

## Context

On Docker Engine 29.2 with Docker Desktop, publishing ports from a container
attached only to an `internal: true` bridge silently produces no host mapping:
`HostConfig.PortBindings` contains the request, but `NetworkSettings.Ports`
is empty. A direct loopback probe fails although Cowrie is healthy. The same
behavior is tracked by [Moby issue #36174](https://github.com/moby/moby/issues/36174)
and [discussion #53256](https://github.com/moby/moby/discussions/53256).
Removing `internal: true` would weaken Cowrie's network boundary.

## Decision

The Cowrie container belongs only to `honeynet`, which remains
`internal: true`. It has no published ports. A separate `cowrie-ingress`
container publishes SSH and Telnet on `${BIND_ADDRESS:-127.0.0.1}` using host
ports `2222` and `2223` by default. It joins `honeynet` and the dedicated
non-internal `cowrie_ingress` bridge; it never joins `prod_net`.
The ingress bridge has the explicit default IPv4 CIDR `172.30.30.0/24`,
separate from `prod_net` (`172.30.10.0/24`) and `honeynet`
(`172.30.20.0/24`). Operators may override the CIDRs for local conflicts.

The ingress uses the existing non-root Nginx image with a separate stream
configuration containing only two TCP proxy targets: `cowrie:2222` and
`cowrie:2223`. It sends the PROXY header so Cowrie records the original client
address. Cowrie listens for PROXY headers on those two ports. The sidecar has
a read-only root filesystem, a small tmpfs, dropped capabilities,
`no-new-privileges`, and resource limits. Nginx's HTTP service remains only on
`prod_net`; neither Target App nor Cowrie joins `cowrie_ingress`.
Compose explicitly selects UID `101` for both Nginx services and UID/GID
`999:999` for Cowrie, matching the accepted images so static policy checks can
verify non-root execution from the normalized configuration.

## Consequences and verification

The ingress is a narrowly scoped bridge between the host-facing network and
Honeynet. A compromise of that sidecar could cross the boundary, so its
configuration, mounts and capabilities are tested statically. Runtime tests
verify loopback SSH/Telnet, raw Cowrie records with preserved client address,
and absence of Cowrie DNS or TCP routes to the HTTP services, host and an
external address. The original two-network topology in the Phase 1 interview
notes is superseded for Cowrie ingress by this decision.
