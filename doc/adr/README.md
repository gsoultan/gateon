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

## Conventions

- File name: `NNNN-kebab-case-title.md` (4-digit, zero-padded, monotonically increasing).
- Status values: `Proposed`, `Accepted`, `Accepted (staged)`, `Superseded by NNNN`, `Deprecated`.
- Keep each ADR focused on a single decision. Link related ADRs explicitly.
