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
| [0007](./0007-xdp-attach-mode-and-the-tc-ingress-hook.md) | XDP attach mode and the TC ingress hook | Accepted |
| [0008](./0008-response-inspection-must-control-its-own-encoding.md) | Response inspection must control its own content encoding | Accepted |
| [0009](./0009-authenticated-ha-heartbeats.md) | Authenticated HA heartbeats and gossip | Accepted |
| [0010](./0010-package-size-ratchet.md) | The package-size limit is a ratchet, not a wall | Accepted |

## Conventions

- File name: `NNNN-kebab-case-title.md` (4-digit, zero-padded, monotonically increasing).
- Status values: `Proposed`, `Accepted`, `Accepted (staged)`, `Superseded by NNNN`, `Deprecated`.
- Keep each ADR focused on a single decision. Link related ADRs explicitly.
