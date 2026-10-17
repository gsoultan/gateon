# 77. The gateway never proxies to cloud instance metadata

Date: 2026-10-17

## Status

Accepted. Co-signed `arch` ↔ `sec`: it moves a trust boundary -- what an
operator may point the data plane at -- and adds a package, `internal/cloudmeta`.
Driver `sec`, Challenger `net` (the dial path and what a backend may be).
Extends ADR 0052, whose save-time and dial-time hooks it reuses.

## Context

An operator (who has `services:write` and `routes:write`, not an
administrator) could save a service whose target was `http://169.254.169.254`
and a `Host()` route to it on a public entrypoint. Every request to that host
was proxied to the cloud instance metadata service from the instance itself:
on EC2, `GET /latest/meta-data/iam/security-credentials/<role>` returns the
instance role's credentials, and IMDSv2 does not help, because the token it
requires is obtained with a `PUT` that a reverse proxy forwards like any other
request. The same held for a TCP service on an L4 route, for a target written
as a name that resolves there (`metadata.google.internal`), and for Alibaba's
`100.100.100.200`, AWS's IPv6 `fd00:ec2::254` and the ECS task credentials
endpoint `169.254.170.2`.

The save-time check (`mgmtaddr.CheckTarget`) and the dial-time hook
(`mgmtaddr.Control`) on every data-plane backend dialer refused only this
gateway's management listener. The technology probe and the diagnostics
test-target already refused link-local addresses for this reason, each with
its own list, and neither list saw a metadata address outside link-local space
(`100.100.100.200` is in 100.64/10, `fd00:ec2::254` is a ULA, Azure's
WireServer `168.63.129.16` is a public address) or an IPv4 address written in
the NAT64 prefix (`64:ff9b::a9fe:a9fe` is `169.254.169.254` to a NAT64
gateway).

## Decision

**One list.** `internal/cloudmeta` is the metadata policy every outbound
connection the gateway makes on someone else's behalf shares. It does no I/O
and does not allocate:

- `Embedded(a)` is the IPv4 address an IPv4-mapped or well-known-prefix NAT64
  (`64:ff9b::/96`) address reaches; every classifier calls it first.
- `IsMetadataAddr(a)` is true for the fixed metadata addresses
  (`169.254.169.254`, `169.254.170.2`, `169.254.170.23`, `169.254.0.23`,
  `100.100.100.200`, `168.63.129.16`, `fd00:ec2::254`, `fd00:ec2::23`) and for
  all of link-local unicast (`169.254.0.0/16`, `fe80::/10`). Of 100.64/10 only
  Alibaba's metadata address is refused; the rest is carrier-grade NAT space
  where backends genuinely live.
- `IsMetadataHost(name)` is true for the names metadata is published under
  (`metadata.google.internal`, `metadata.goog`, `instance-data.ec2.internal`,
  Tencent's and Equinix's). The short names `metadata` and `instance-data` are
  not listed: they are also plausible names for a Kubernetes or compose
  service, and where they do resolve to a metadata service the dialer refuses
  the address.

**Refused at save and at dial**, through the hooks ADR 0052 installed:

1. `mgmtaddr.CheckTarget`, called by the domain `SaveService` that every
   writer of a service goes through, refuses a target whose host is a metadata
   address (any form, any port, any TCP scheme, or a bare host) or name, with
   `ErrInvalidService` naming the target. Names are not resolved at save for
   this check: the dial check covers them, and a save should not wait on DNS
   for every target.
2. `mgmtaddr.Control`, the `net.Dialer` Control hook on the proxy's
   `backendDialer` (HTTP/1, HTTPS, h2, h2c, PROXY protocol, WebSocket, health
   checks), on `pkg/l4`'s TCP backend dialer and on forward-auth, refuses the
   connection with `ErrCloudMetadata` on the resolved address, so a name that
   resolves to `169.254.169.254` -- now or after the save -- is refused before
   `connect(2)`, and services from configuration files, GitOps and discovery,
   which do not pass through the save, are covered. A refused request is a
   502 and the health check counts the target down. It is logged at WARN at
   most once a minute. The check is a few comparisons and allocates nothing,
   and it now runs on every backend connection rather than only one to the
   management port's number.

**The probes use the same list.** The technology probe's `blockedProbeTarget`
(and the gRPC discovery that shares it) and the diagnostics test-target's
`isBlockedIP` judge an address through `Embedded` and add `IsMetadataAddr`, so
they now refuse NAT64 forms of what they already refused, and the metadata
addresses outside their ranges. The probe keeps refusing all of link-local
regardless of the escape hatch below.

**Escape hatch: `GATEON_ALLOW_LINK_LOCAL_TARGETS=1`**, default off, read once
at startup. Link-local space has real backends: a node-local DNS cache on
`169.254.20.10`, a device on a LAN reached by its `fe80::` address. Setting it
permits link-local targets *except the fixed metadata addresses*, which no
setting reopens. It is an environment variable rather than a dashboard setting
on purpose: it is the operator of the host, not an operator of the gateway,
who knows whether the instance has a metadata service worth protecting.

## Consequences

- An existing service whose target is a metadata address stops proxying on
  upgrade (502; its health check reports it down) and can no longer be saved
  unchanged. A service on another link-local address does the same until
  `GATEON_ALLOW_LINK_LOCAL_TARGETS=1` is set. See `doc/upgrading.md`.
- UDP services are not checked: no metadata service answers UDP, the L4 UDP
  path dials without a Control hook, and a node-local DNS cache is the common
  link-local UDP backend.
- A metadata name not on the list that resolves to an address not on the list
  (a provider that publishes its metadata on a routable address) is not
  caught. The list is the place to add one.
