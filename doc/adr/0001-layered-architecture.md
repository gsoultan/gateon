# ADR-0001: Layered, domain-oriented architecture

- **Status:** Accepted
- **Date:** 2026-06-15

## Context

Gateon is a security-focused HTTP/gRPC/L4 gateway (~37k LOC of Go). As the feature
set grew (WAF, ClamAV, eBPF, anomaly detection, IP reputation, zero-trust, audit log,
TLS/JA3 fingerprinting), the codebase needed a consistent way to separate transport
concerns from business logic and data access so that:

- new transports (gRPC, HTTP, SSE, WebSocket, message queue) can be added without
  duplicating business rules;
- business logic is testable in isolation from HTTP/gRPC plumbing;
- onboarding is predictable — a contributor can locate a concern by its layer.

## Decision

Adopt a **layered, domain-oriented** architecture, organizing code by domain under
`internal/<domain>` rather than by technical layer, and within each domain follow a
single execution flow:

```
Transports → Middlewares → Endpoints → Services → Usecases → Repositories
```

- **Transports** (`internal/server/...`, gRPC/HTTP/SSE/WS): entry points for external
  communication; thin adapters that decode/encode and delegate.
- **Middlewares** (`internal/middleware`): cross-cutting concerns (auth, WAF,
  rate-limit, transforms, observability). See ADR-0002 for its internal structure.
- **Endpoints**: the seam between transport and business logic.
- **Services** (`internal/domain/<domain>`): orchestration; one service may compose
  multiple usecases. A service facade groups services for a domain.
- **Usecases**: atomic business operations.
- **Repositories** (`internal/config`, `internal/telemetry` stores): data access,
  split into `entities` (DB models) and `stores` (per-vendor implementations).

Cross-cutting principles (from `.junie/agents.md`):

- **Accept interfaces, return structs**; define interfaces where consumers need them
  (one interface per file, one struct per file where practical).
- **Keep handlers thin** — push logic into `internal/domain`.
- **Folder readability:** ≤10 files per folder; 5–9 top-level child directories;
  split a folder by domain/functionality once it exceeds 10 files.
- **SQL externalization:** queries live in `.sql` files embedded via `//go:embed`.
- **Security-first, type-safe, thread-safe**; `go test -race ./...`.

## Consequences

- Positive: clear ownership boundaries, testable business logic, room for new
  transports, consistent navigation.
- Negative / cost: some packages currently violate the ≤10-files rule (notably
  `internal/middleware`, 65 non-test files) and must be refactored incrementally —
  tracked by ADR-0002 to avoid a single high-risk change.
- The functional-options dependency injection already used by `server.NewServer(...)`
  is the preferred construction pattern; extend it to security managers for testability.

## Alternatives considered

- **Layer-first packaging** (`internal/handlers`, `internal/models`, `internal/services`):
  rejected — it scatters a single feature across many packages and encourages
  god-packages.
- **Flat package** (status quo for `internal/middleware`): rejected for large domains —
  it exceeds the readability threshold and hides cohesive sub-domains.

## Related

- ADR-0002 — middleware package refactor.
- ADR-0003 — configuration store interfaces.
- `doc/architecture.md` — dependency diagram of the layers and middleware groupings.
