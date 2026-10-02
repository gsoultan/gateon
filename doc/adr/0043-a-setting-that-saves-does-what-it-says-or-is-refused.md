# 43. A setting that saves does what it says, or is refused

Date: 2026-10-02

## Status

Accepted. `sec` co-signs with `data` (route rules, block lookups) and `ux`
(the dashboard forms): each decision moves what the gateway accepts at a trust
boundary -- which route a request reaches, who authenticates, which tokens and
which addresses are refused.

## Context

The 2026-10-02 review found four settings that were accepted with a success and
then did the unsafe thing, silently:

- **A7 -- a route rule with a typo matched every request** (ops F2). The rule
  parser looked for each condition by substring and ignored whatever it did not
  recognise. An unclosed quote or parenthesis, `Hots()` for `Host()`, a regular
  expression that did not compile, an empty value: each produced a matcher with
  no condition, which matches everything. `PUT /v1/routes` answered 200, the
  route took the entrypoint's traffic from the routes that described it -- and
  with it their auth and WAF -- survived restarts, and logged nothing. The same
  parser also dropped conditions it could read: a second `PathPrefix` (so
  `PathPrefix(`/api`) && !PathPrefix(`/api/admin`)` did not exclude admin),
  grouping parentheses, and a leading `!` negated the whole rule.
- **A8 -- a basic-auth user with an empty password let anyone in** (truth T2).
  The dashboard's "Add user" row appends `user<N>:`; the save stored it; the
  verifier compared the empty password a request sent with the empty one
  configured.
- **A9 -- OIDC or JWKS-verified JWT with "Audience (optional)" blank accepted a
  token issued to any other application of the same provider** (truth T5): the
  provider's keys sign every client's tokens, and with no audience nothing
  told them apart. For a public provider, any application at all.
- **A10 -- a database error made the block list answer "not blocked", and that
  answer was cached with no expiry** (dataplane F3). `IsIPMitigated` cached the
  answer to a failed lookup in an ARC with no TTL, so a blocked address was
  served during the error and after recovery, until eviction.
  `IsUserMitigated` had the same shape, over a block it already held.

## Decision

### A7 -- one parser, refused at save, inert at runtime

The rule grammar has one implementation, `internal/router/rule`, used by the
route save and by the router, so a rule the gateway accepted is exactly the rule
it runs:

    expr    = and { "||" and }
    and     = unary { "&&" unary }
    unary   = { "!" } primary
    primary = "(" expr ")" | name "(" [ value { "," value } ] ")"
    value   = "`" text "`" | `"` text `"`        (literal, no escapes)

Conditions are `Host`, `HostRegexp`, `Path`, `PathPrefix`, `PathRegex`,
`Methods`, `Headers` and `L4()` (what the dashboard writes for TCP/UDP routes,
whose traffic is chosen by entrypoint; it matches as before). `!` binds to the
condition it precedes; parentheses group, at most 32 deep. An empty value, a
regex that does not compile, a wrong number of values, an unknown name (with a
"did you mean" for a typo) and anything left over are errors, each naming the
character where reading stopped.

- **Save.** The domain `SaveRoute` -- the one chokepoint REST, gRPC and config
  import share, as ADR 0038's guard uses it -- refuses a rule that does not
  parse: `400` on REST, `InvalidArgument` on gRPC, a per-route error on import,
  and the import preflight (`/v1/config/validate`) refuses it too. A TCP/UDP
  route may have no rule; one it has must still parse.
- **Runtime.** A stored rule that does not parse -- an old database, a
  hand-written routes file, a Kubernetes-synced route -- matches nothing, and is
  logged once, when the router first meets it. The matcher is cached per rule
  text, so it costs a map load afterwards.

Matching got faster (-35%, `BenchmarkSelectRouteFromSlice`, 0 allocations both
sides), because the request host is resolved once per rule instead of once per
`||` branch.

### A8 -- an empty password is never a credential

`parseBasicUsers` refuses a user with no password or no name, naming the user
and saying why. The save builds the middleware, so REST, gRPC and import refuse
it; a stored list fails to build and the router serves the 503 refusal of an
unbuildable security middleware. Independently, a request with an empty name or
password never authenticates, whatever the configured check says. A user whose
password is stored keeps it through the write-only placeholder (ADR 0033); the
dashboard flags a row with no password and keeps Save disabled until it has one.

### A9 -- a key set needs an audience

`NewJWTValidator` with a JWKS URL and `NewOIDCValidator` refuse to build without
an audience (`ErrAudienceRequired`, which says why); OIDC refuses before it asks
the provider anything. A JWT checked against a shared secret still needs none:
that secret is this gateway's alone. The one way to accept any audience is the
named opt-out `allow_any_audience=true`, for a provider that issues tokens to
this gateway alone -- never a blank field. The dashboard marks the audience
required where it is, says why, and offers the opt-out as a red switch.

**Existing configs without an audience fail closed:** they no longer build, and
their routes answer 503 until an audience (or the opt-out) is set. That is the
behaviour of every unbuildable security middleware (ADR 0033, the router's
criticality list). Silently keeping them working would keep the hole; the
upgrade note says so loudly.

### A10 -- an error is not an answer

- A failed lookup is never cached. `readIPShunUntil` and `readUserMitigated`
  return an error when the database cannot answer, distinct from "no row".
- A shun in force stays cached until it ends. "Not blocked" is cached for one to
  two minutes -- the epoch it was read in and the next -- and then read again,
  so a block written by another node, or straight to the database, is enforced
  within two minutes; it was unbounded. The epoch is an atomic that the store's
  existing minute ticker advances, so the answer nearly every request gets reads
  no clock (`BenchmarkIsIPMitigatedNotShunned`: no change, 0 new allocations).
- A fingerprint blocked again after an operator's release is blocked: the
  release override the cache holds is dropped by the new block. It outlived the
  block before, until eviction.
- Failures are counted in `gateon_mitigation_lookup_errors_total{kind="ip"|"user"}`
  and logged at most once a minute.

**During a database outage the request is served (fail open), except where this
node's cache holds a block in force.** The reasons:

- The data plane keeps serving while the database is down; that is a property
  operators rely on. Refusing every address the cache cannot vouch for would
  turn a database outage into a total outage of every route.
- It would be a denial of service anyone can trigger wherever load alone
  produces errors -- SQLite's `SQLITE_BUSY` past the busy timeout, an exhausted
  Postgres pool.
- What the block list loses is bounded: blocks this node has seen stay enforced
  from the cache, for addresses (until the shun ends) and fingerprints (a cached
  block is kept on error). The gap is a block this node has not looked up since
  it started, during the outage. It is enforced from the first lookup after the
  database answers -- which is what the old code got wrong.

## Consequences

- Operators may see routes, auth middlewares or imports refused that saved
  before; each refusal names the fault. Stored ones keep the gateway safe (a
  route that matches nothing, an auth middleware that refuses with 503) until
  they are fixed. See the upgrade note.
- A rule that relied on the old reading changes meaning only where the old
  reading was wrong: a leading `!` now negates the condition it precedes, not
  the whole rule; a second condition of the same kind is honoured; parentheses
  group.
- The dashboard's rule builder writes values literally; it used to double every
  backslash, again on every save, which broke regexes.
- The config index (`internal/config/routes.go`) still picks host and path
  buckets by substring. It only narrows candidates and the parsed rule decides,
  so it cannot make a rule match more than the rule says; it can make an
  `||`-of-hosts rule match less (only the first host is indexed). Left as is.

## Alternatives considered

- **Reject only the review's four shapes.** Every other way the substring
  parser could fail to read a rule would remain a match-all.
- **Refuse to start with an unparsable stored rule.** One typo would take the
  whole gateway down on the next restart; matching nothing confines it to the
  one route.
- **Keep OIDC/JWKS without audience working and warn.** A warning in a log does
  not stop a token minted for another application.
- **Fail closed on a block-lookup error.** See A10: an availability failure any
  client can provoke, for a gap the cache already narrows.
- **A clock-based TTL for "not blocked".** Measured +86% on the cached lookup
  (`time.Now()` on every request); the epoch costs an atomic load.
