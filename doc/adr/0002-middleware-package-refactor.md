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
- **Measured 2026-09-03: the two shipped stages did not shrink the package.** This
  ADR recorded 65 non-test files on 2026-06-15. Stages 0 and 1 extracted roughly
  thirteen into `kind` and `auth`, and `internal/middleware` today holds **67** —
  two more than before the refactor started. New middleware landed in the root
  package faster than the extraction drained it, and `internal/middleware/auth`,
  which this ADR promised would land inside the ten-file budget, has since grown to
  eleven. The staged plan below is unchanged and still correct; what it was missing
  is something stopping the parent package from growing underneath it while the
  stages land. ADR-0010 adds that ratchet, so the remaining stages keep their
  ground instead of spending it.

- **Stage 2 (`traffic`) is done, 2026-09-20:** ratelimit, connlimit, maxbody,
  inflight, retry, cache and compress moved to `internal/middleware/traffic` --
  13 files, taking `internal/middleware` from **67 to 54**. The first stage that
  actually shrank it; the ratchet in ADR-0010 is what keeps that ground, and its
  pin was lowered to 54 in the same commit as the move.

  The coupling turned out to be far lower than feared. A scratch-package probe
  reported only two undefined symbols across all thirteen files, and the real
  total came to eleven: `Middleware`, `GetRouteName`, `ShouldSkipMetrics` and
  `IsCorsPreflight` already lived in `kind`; `StatusResponseWriter` and its pool
  are in `pkg/httputil`; and four parse helpers plus the severity/action
  vocabulary moved into `kind` as `ParsePositiveInt`, `ParseIntStrict`,
  `ParseBoolStrict`, `ParseListStrict` and `Severity*`/`Action*`.

  Moving those last two groups is the part worth repeating for later stages.
  `parseListStrict` was defined in `compress_factory.go` -- a file this stage
  moved -- while `cors_factory.go`, which stays, was calling it: a shared helper
  can sit in any file, so the compiler, not the file list, decides what a stage
  actually owns. The severity and action constants went to `kind` rather than
  being copied because the 2026-09-19 review traced a real defect to exactly
  that vocabulary existing in two spellings.

  Five `Factory` methods became exported constructors -- `NewRateLimit`,
  `NewCache`, `NewCompress`, `NewBuffering`, `NewInflightReq` -- taking the
  `redisClient` and `ebpfManager` they had been reading off the receiver.
  `cache_test.go` stayed behind: it builds through `f.Create` on purpose, "the
  way ApplyRouteMiddlewares does", and a subpackage cannot import the factory
  without a cycle. Only its `cacheStore` unit test moved.

  `internal/middleware/traffic` is pinned at 13 rather than split further,
  because ADR-0002 names it as one group and splitting it again is a structural
  change this ADR does not describe. Verified with `go build ./...`,
  `go vet ./...` and `go test -race ./...` -- 62 packages, all green.

- **Stage 3 (`transform`) is done, 2026-09-20:** cors, headers, rewrite, xfcc,
  grpcweb, wasm and the body transform moved to
  `internal/middleware/transform` -- 11 files, taking `internal/middleware`
  from **54 to 43**. Two stages in one day took it from 67 to 43; the pin
  follows in the same commit, and `transform` is pinned at 12 on the same
  reasoning as `traffic`.

  The probe technique from Stage 2 is now the way to start one of these. A
  scratch package built from the group reported two undefined symbols, and
  resolving those revealed the next wave -- the errors arrive in layers, so the
  probe has to be run more than once before the number means anything. Total
  came to seven, all already solved by earlier stages except two.

  Both of those were files in the wrong place, and in opposite directions.
  `headerAccept` was defined in `cors_factory.go`, which moved, and used by
  `pow.go`, which stayed -- the same shape as `parseListStrict` in Stage 2, so
  it is a pattern rather than an accident. Both header constants now live in
  `kind`, which also removes the local copy Stage 2 made. `spanLogger` was the
  mirror image: defined in `otel.go`, which stays, used only by `cors.go` and
  `grpcweb.go`, which move, and referenced by nothing in its own file. It moved
  with the group it serves.

  Two tests stayed in `package middleware` because they build through
  `f.Create` -- `transform_test.go` in full, and the transform entry of
  `TestResponseWriterWrappersPreserveHijacker`, which was split rather than
  dropped: that guard exists because a wrapper forgetting to forward Hijack
  broke WebSocket upgrades in production, and exporting an internal wrapper so
  another package could name it would be a worse trade than two tests.

  Verified with `go build ./...`, `go vet ./...` and `go test -race ./...` --
  63 packages, all green.

- **Stage 4 (`security`) is done, 2026-09-20:** the WAF, the challenge
  middlewares, fingerprint identity, network access control, API-shape
  validation and content inspection moved to `internal/middleware/security`
  -- 34 files, taking `internal/middleware` from **43 to 12**. Sixty-seven to
  twelve in three stages over one day.

  This stage is where the ADR's own partition turned out to be wrong. Stages 2
  and 3 named groups that were genuinely one concern each, and their pins say
  so. "Security" is not one concern: it is six that share an adjective. The pin
  at 34 records that rather than dressing it up, and the ratchet will not let
  it grow while the follow-on split is outstanding.

  Nine `Factory` methods became package-level constructors taking a `Deps`
  struct -- `GlobalStore`, `EbpfManager`, `Reputation`, `DataDir`, `RouteType`,
  the five factory fields this group actually read. `CreateGlobalWAF` is the
  one that stayed a method, because `internal/router` calls it and the router
  has no business assembling another package's dependencies; it is now a
  two-line delegation.

  That delegation is the stage's one real risk and it has its own test. The
  behavioural WAF tests moved to sit against `NewGlobalWAF`, which left nothing
  checking that the factory forwards its fields -- and a field dropped from
  `securityDeps()` still compiles, producing a global WAF built from a zero
  value. For `GlobalStore` that means a gateway with the WAF enabled serving
  every route unprotected, silently. `global_waf_wiring_test.go` asserts the
  forwarding directly, and was negative-tested by deleting each field.

  Two things the move broke and the suite caught. `testdata/benign` did not
  follow the false-positive corpus into the new package, and the FP gate
  refused to pass vacuously -- the guard written for exactly this, working. And
  a blanket identifier rewrite put `security.` in front of prose inside
  comments and test-failure strings ("the security.WAF store"); scrubbing it
  needed a parser that could tell a comment from a source position, because
  three of the hits were genuine cross-package references and had to stay.

  The next extraction is the WAF cluster, and it is already proven cheap. The
  ratchet's original text called those ten files blocked because they "all
  reach for Middleware, Factory, RequestState and Chain, which are defined
  elsewhere". This ADR moved exactly those, and a scratch-package probe now
  builds all ten against nothing but the shared `Deps` type -- which the WAF
  reads all five fields of, against three for the rest of the package.

## Related

- ADR-0001 — layered architecture and the ≤10-files rule.
- `doc/architecture.md` — current dependency diagram and target grouping.
