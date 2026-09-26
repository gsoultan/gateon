# Architecture Decision Records (ADRs)

This directory captures the significant architectural decisions for Gateon. Each
record is immutable once accepted; superseding decisions are added as new ADRs that
reference the ones they replace.

ADRs follow a lightweight [MADR](https://adr.github.io/madr/)-style format:
**Context → Decision → Consequences**, plus status and alternatives.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](./0001-layered-architecture.md) | Layered, domain-oriented architecture | Accepted |
| [0002](./0002-middleware-package-refactor.md) | Staged refactor of `internal/middleware` into cohesive subpackages | Accepted (staged) |
| [0003](./0003-config-store-interfaces.md) | Per-domain `Store` interfaces over a single mega-store | Accepted |
| [0004](./0004-waf-engine-replacement.md) | Replace the Coraza WAF engine with gwaf | Accepted |
| [0005](./0005-session-lifecycle-and-first-run-trust.md) | Session lifecycle and first-run trust | Accepted |
| [0006](./0006-transport-neutral-authorization.md) | Transport-neutral authorization for the management API | Accepted |
| [0007](./0007-xdp-attach-mode-and-the-tc-ingress-hook.md) | XDP attach mode and the TC ingress hook | Accepted; TC parts superseded by 0017 |
| [0008](./0008-response-inspection-must-control-its-own-encoding.md) | Response inspection must control its own content encoding | Accepted |
| [0009](./0009-authenticated-ha-heartbeats.md) | Authenticated HA heartbeats and gossip | Accepted |
| [0010](./0010-package-size-ratchet.md) | The package-size limit is a ratchet, not a wall | Accepted |
| [0011](./0011-reputation-is-scoped-to-a-network.md) | A reputation score belongs to a browser on a network, not to a browser | Accepted |
| [0012](./0012-session-revocation-propagates-but-expiry-guarantees.md) | Session revocation propagates over Redis, but expiry is what guarantees it | Accepted |
| [0013](./0013-fingerprint-identity-is-its-own-package.md) | Fingerprint identity is its own package | Accepted |
| [0014](./0014-backend-client-identity-is-the-gateways-choice.md) | The backend client identity is the gateway's choice | Accepted |
| [0015](./0015-cors-is-decided-per-route.md) | CORS is decided per route, and a backend's own policy wins | Accepted |
| [0016](./0016-per-route-state-is-keyed-by-route-id.md) | Per-route state is keyed by the route's ID; its name is a label | Accepted |
| [0017](./0017-ebpf-falls-back-to-tc-on-its-own.md) | eBPF falls back to the TC hook on its own, and the TC hook enforces what it claims | Accepted |

## Conventions

- File name: `NNNN-kebab-case-title.md` (4-digit, zero-padded, monotonically increasing).
- Status values: `Proposed`, `Accepted`, `Accepted (staged)`, `Superseded by NNNN`, `Deprecated`.
- Keep each ADR focused on a single decision. Link related ADRs explicitly.
