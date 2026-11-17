# 95. A route is checked against the API it publishes

Date: 2026-11-16

## Status

Accepted. `sec` drives (a positive check is a new deny decision); `ux`
challenges what an operator is told when it refuses; `mem` challenges what a
pasted document may cost; `arch` co-signs where the code lives.

## Context

Every other check in the WAF is negative: it names what an attack looks like
and refuses that. A request exploiting a flaw nobody has described yet matches
no rule. The CVEs that prompted this work (a traversal through a parameter that
should have been an integer, an injected value in a field that should have been
one of four words) all sent something the API's own description forbids.

gwaf can refuse on that description: `gwaf.WithSchema` takes compiled
operations, and `schema/openapi` compiles an OpenAPI 3 document into them.
Gateon did not use either. What it had instead was
`internal/middleware/security/openapi.go`, a validator that logged a debug line
and forwarded every request. Nothing constructed it, so no dashboard setting
claimed protection it did not give, but it was a file whose name said the
feature existed.

Two things make a positive check dangerous to switch on. A published document
is nearly always narrower than the traffic an API really serves: an
undocumented parameter, a client that sends a number as a string. And a refusal
caused by the operator's own document is not evidence about the client, yet a
WAF block feeds reputation and the automatic ban.

## Decision

A WAF middleware takes two more settings, `openapi_spec` (the document, YAML or
JSON, at most 1 MiB) and `openapi_mode` (`record`, the default, or `enforce`).

1. **Recording is the default and is a real mode, not a log line.** gwaf
   evaluates the schema and reports the violation without acting on it
   (`gwaf.WithSchemaMode(gwaf.SchemaObserve)`). Gateon forwards the request,
   counts it in `gateon_middleware_waf_schema_violations_total{route,violation,mode}`
   and lists it in the Security Hub under `api_schema`. The rest of the WAF
   decides exactly as it would have without a document.
2. **Enforcing answers 403 before the backend.** The block is recorded like any
   other, with the parameter and the constraint it broke.
3. **A schema refusal is held against nobody.** It adds no reputation penalty
   and does not count towards an automatic block. One wrong line in a document
   must not ban every customer who sends that parameter.
4. **Audit Only wins.** A route in audit-only records, whatever the mode says,
   and the form says so beside the mode.
5. **The schema is open.** A path or method the document does not describe is
   not checked. Refusing undescribed paths is routing policy, which the route
   table already expresses.
6. **A document that cannot be used refuses the save.** Too large, not OpenAPI,
   no paths, or an unknown mode fails the middleware build, and `SaveMiddleware`
   builds before it persists. A document that compiles but constrains nothing
   is accepted and logged as a warning with the count of fields it could not
   use.
7. **Compiled once.** The document is compiled when the engine is built and the
   engine cache key carries its SHA-256 and the mode, so an edit rebuilds and a
   request never parses YAML.

The glue lives in a new package, `internal/security/waf/apischema`, because
both WAF packages are at their file limit (`make check-folders`). The dead
validator is deleted and the pin for `internal/middleware/security` drops from
15 to 14 in the same commit.

## Consequences

- An operator can paste a document, watch what it would have refused for a
  week, and only then enforce. That is the rollout the DLP action already
  follows.
- The Security Hub entries for recorded violations are capped at five a second
  per engine; the metric counts all of them. A misdescribed parameter on a busy
  route would otherwise write one event per request.
- The label `violation` takes gwaf's fixed set of violation kinds and `mode`
  two values, so the metric is bounded by the number of routes.
- Memory: one compiled schema per distinct (document, mode, rest of the WAF
  configuration), bounded by the 1 MiB input cap and the engine cache.
- No migration and no proto change: middleware configuration is already a
  string map.
- No environment variable: the document belongs to one route's API, so there is
  no deployment-wide value to set, and no tier default, because with no
  document the check does not run.
- Request bodies are checked only as far as gwaf's schema compiler supports
  them; the build log reports how many declared fields were skipped. Response
  validation is not part of this.
- gwaf must be at a version that has `WithSchemaMode`. Until it is tagged,
  `go.mod` pins a commit.
