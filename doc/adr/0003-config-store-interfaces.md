# ADR-0003: Per-domain `Store` interfaces over a single mega-store

- **Status:** Accepted
- **Date:** 2026-06-15

## Context

The original review flagged a "dual source of truth": file-based JSON registries
(`routes.json`, `services.json`, …) alongside DB-backed access, and suggested a single
`Store` interface with file/DB/etcd backends so the rest of the code is storage-agnostic.

On closer inspection, `internal/config` **already** exposes consumer-side abstractions,
one per domain, each defined in its own file (one-interface-per-file, ADR-0001):

- `RouteStore` (`route_store.go`) — implemented by `RouteRegistry` (`routes.go`)
- `ServiceStore` (`service_store.go`)
- `MiddlewareStore` (`middleware_store.go`)
- `EntryPointStore` (`entrypoint_store.go`)
- `TLSOptionStore` (`tls_option_store.go`)
- `GlobalConfigStore` (`global_config_store.go`)

These share a common CRUD shape (`List`, `ListPaginated`, `All`, `Get`, `Update`,
`Delete`). The current concrete implementation is file/JSON-backed registries; the
domain services in `internal/domain/<domain>` already depend on the **interfaces**, so
the storage backend is swappable without touching business logic.

## Decision

**Keep per-domain `Store` interfaces; do not collapse them into one mega-store.**

Rationale:

- A single `Store[T any]` would either lose type safety or require runtime
  type-switching for entity-specific queries (`ListPaginated` filters differ per domain,
  e.g. `RouteFilter`).
- Per-domain interfaces already satisfy "accept interfaces, return structs" and keep
  consumers storage-agnostic — the stated goal — without a risky rewrite.

To remove the remaining duplication and enable DB/etcd backends, evolve **behind the
existing interfaces**:

1. Introduce a generic helper `type crudStore[T proto.Message] interface { ... }` to
   factor the shared CRUD shape and reduce per-domain boilerplate (composition, not
   replacement).
2. Add alternative backends as new implementations of the same interfaces
   (`stores/postgres`, `stores/etcd`), selected by config — file registries remain the
   default.
3. Make the active backend explicit in config so there is a single source of truth at
   runtime (file **or** DB/etcd, not both silently).

## Consequences

- Positive: no churn for existing consumers; type-safe, per-domain queries preserved;
  backends become a config choice.
- Positive: low risk — additive change, interfaces already in place.
- Negative / cost: a small amount of CRUD boilerplate remains until the generic helper
  is introduced; multiple backends must be kept behaviorally consistent (covered by a
  shared interface conformance test suite).

## Alternatives considered

- **Single mega-`Store` interface for all domains:** rejected — erases type safety and
  forces runtime type-switching for domain-specific pagination/filtering.
- **Status quo (no generic helper):** acceptable short-term but leaves duplicated CRUD.

## Related

- ADR-0001 — layered architecture (repositories layer, one-interface-per-file).
