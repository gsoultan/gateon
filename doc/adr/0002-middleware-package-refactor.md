# ADR-0002: Staged refactor of `internal/middleware` into cohesive subpackages

- **Status:** Accepted (staged)
- **Date:** 2026-06-15

## Context

`internal/middleware` currently holds **65 non-test Go files** (73 incl. tests) in a
single flat `package middleware`. This violates the ≤10-files-per-folder readability
guideline (ADR-0001) and mixes unrelated concerns — authentication, WAF/security,
traffic shaping, and request/response transforms — in one namespace.

A naive "move files into subdirectories" refactor **does not compile** because of an
import cycle:

- The core type `Middleware func(http.Handler) http.Handler` and helpers (`Chain`,
  `Recovery`, context keys, `status_writer`, `errors`) are defined in
  `package middleware` (`middleware.go`).
- A subpackage (e.g. `middleware/auth`) would need that `Middleware` type, so it must
  import `package middleware`.
- But `factory.go` (in `package middleware`) dispatches to every middleware and would
  import `middleware/auth` — creating `middleware ⇄ middleware/auth`.

Additionally, construction is centralized: `factory.go` is a `switch m.Type` that calls
unexported methods (`f.createAuth`, `f.createRateLimit`, …) defined across the
`*_factory.go` files as methods on `*Factory`. Moving a middleware out requires turning
its factory method into an exported constructor the parent calls.

## Decision

Refactor in **safe, independently-shippable stages**; never leave `main` non-compiling.

### Stage 0 — Break the cycle (foundation)

Extract the cycle-free core into a leaf package that everything else imports:

- New `internal/middleware/kind` (leaf): `type Middleware`, `Chain`, `Recovery`,
  `ContextKey` + keys, `DebugInfo`, `status_writer`, shared `errors`, small predicates
  (`IsInternalPath`, `IsCorsPreflight`, …).
- In `package middleware`, keep backward compatibility with **type aliases** so the 65
  existing files keep compiling unchanged during migration:
  `type Middleware = kind.Middleware`, `var Chain = kind.Chain`, etc.

### Stage 1..N — Move one cohesive group at a time

For each group below: move its files to the subpackage, change factory methods into
exported constructors, update `factory.go` to call `auth.New...`, run
`go build ./... && go test -race ./...`, then ship.

| Subpackage | Files (illustrative) | Concern |
|------------|----------------------|---------|
| `middleware/kind` | middleware.go (core), status_writer.go, errors.go | shared primitives (Stage 0) |
| `middleware/auth` | auth*, forwardauth*, hmac*, oauth2_introspection, oidc_*, paseto_verifier, apikey_store, revocation, tls_binding | authN/authZ |
| `middleware/security` | waf*, security_advanced, graphql_firewall*, schema_validation, openapi, file_security, bot_management*, deception, honeypot, pow, turnstile*, tls_fingerprint, geoip*, ipfilter_factory, policy* | WAF & threat defense |
| `middleware/traffic` | ratelimit*, connlimit, maxbody, inflight_factory, retry, cache*, buffering_factory, compress* | rate/traffic shaping |
| `middleware/transform` | headers_factory, rewrite*, transform, cors*, standard (prefix), grpcweb, wasm, xfcc* | request/response transforms |
| `middleware` (root) | factory.go, factory_parse.go | dispatch/registration only |

### End-state registration

Replace the monolithic `switch` with a small **registry/factory map**: each subpackage
registers its `type → constructor` entries (Strategy pattern), so the root package
depends on subpackages but not vice-versa, and adding a middleware no longer edits a
giant switch.

## Consequences

- Positive: each folder lands within the ≤10-files budget; concerns are isolated and
  independently testable; the registry removes the central switch hot-spot.
- Positive: every stage is behavior-preserving and verifiable (`-race`), so the repo
  stays production-ready between stages.
- Negative / cost: temporary type aliases during migration; touching `factory.go`
  repeatedly; care needed where middlewares share unexported helpers (move those into
  `kind` first).

## Status of execution

- This ADR + `doc/architecture.md` are delivered.
- **Stage 0 is done:** the cycle-free core now lives in `internal/middleware/kind`
  (`core.go` — `Middleware`, `Chain`, `Recovery`, `SecurityHeaders`, `ContextKey` +
  keys, `DebugInfo`, path predicates; `status_writer.go` — pooled
  `StatusResponseWriter` + `StatusString`; `errors.go` — custom-error-page
  middleware). `package middleware` now keeps only transparent aliases
  (`middleware.go`) so all 60+ remaining files and external callers compile
  unchanged. Verified with `go build ./...`, `go vet`, `gofmt`, and a new
  table-driven `kind/core_test.go`.
- **Stage 1 (`auth`) is done:** the authentication/authorization middlewares were
  moved into the new cohesive subpackage `internal/middleware/auth` (`package auth`):
  `auth.go`, `auth_utils.go`, `forwardauth.go`, `hmac.go`, `oauth2_introspection.go`,
  `oidc_proxy.go`, `oidc_validator.go`, `paseto_verifier.go`, `apikey_store.go`,
  `revocation.go` (10 files) + a small `aliases.go` re-exporting the cycle-free
  `kind` primitives it needs (`Middleware`, `IsCorsPreflight`, `GetRouteName`,
  `ShouldSkipMetrics`). `package middleware` keeps a transparent re-export shim
  (`auth_aliases.go`) so the factory dispatch, the package tests, and all external
  callers (`middleware.JWTValidator`, `middleware.PasetoAuth`,
  `middleware.UserContextKey`, …) compile unchanged. `tls_binding.go` was kept in
  `package middleware` for now because it depends on the security-group helper
  `recordAdvancedThreat`; it will move with the `security` group. Verified with
  `go build ./...`, `go vet`, `gofmt`, and the middleware/server/api tests.
- The remaining per-group moves (`security`/`traffic`/`transform`) and the
  registry-based dispatch are **still tracked, not yet executed** — each is its own
  shippable session to honor the "production-ready every session" rule. Tracked in
  `doc/recommendations.md` (Session 7).

## Related

- ADR-0001 — layered architecture and the ≤10-files rule.
- `doc/architecture.md` — current dependency diagram and target grouping.
