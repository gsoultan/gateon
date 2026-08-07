# 4. Replace the Coraza WAF engine with gwaf

Date: 2026-08-06

## Status

Accepted.

## Context

gateon's WAF was OWASP Coraza loading the OWASP Core Rule Set, plus 75 SecLang
directives seeded into the `waf_rules` table on every install. The engine was
bound to gateon in `internal/middleware/waf.go`, a 2,052-line file that built
the engine by concatenating about twenty SecLang directives into a string.

Four things about that arrangement were costing more than they returned.

**Rules were configuration, not code.** A directive with a typo produced a rule
that silently never fired, and nothing could check it. The 75 defaults were rows
in every install's database, so each deployment carried its own drifting copy of
what was supposed to be gateon's ruleset, and no test covered the combination
actually running anywhere.

**Two workarounds existed only to appease CRS.** The CRS protocol-enforcement
rules refuse gRPC content types and reject `OPTIONS`, so gateon injected
compatibility directives, disabled request-body inspection for gRPC entirely,
and bypassed the WAF for CORS preflights. The second of those is a real hole:
gRPC bodies were not inspected at all.

**Reputation travelled through the request.** gateon wrote its verdict into
`X-Gateon-Reputation` and wrote SecRules that read it back. Because the value
travelled as a header, gateon also had to strip six `X-Gateon-*` headers from
client input on every request. Miss one and a client asserts its own reputation.

**The dashboard's vocabulary was CRS's.** Explanations were a map keyed by CRS
rule number and categories were derived from numeric ID ranges, so the security
UI was coupled to somebody else's ruleset numbering.

## Decision

Replace Coraza with [gwaf](https://github.com/gsoultan/gwaf) v0.1.0, and remove
SecLang from gateon entirely.

Because the two engines are not run side by side, no engine-abstraction
interface was introduced: an interface with a single implementation is
speculative generality, and the seam it would create is exactly the seam that
made the old file hard to read. `waf.go` was split by responsibility instead.

Specifically:

- **Rules are compiled into the binary.** The 75 seeded directives became 57
  typed `rules.Rule` values in `internal/security/waf/ruleset.go`, keeping their
  original IDs so threat history and operator-written exceptions still resolve.
  Migration 60 deletes the seeded rows.
- **Stored rules use a typed JSON format** (`Definition`), not SecLang. A rule
  still in SecLang is kept, flagged, and **not enforced** — refusing to run it is
  honest where guessing at it would not be.
- **Suppression is an exception, not a generated rule.** The false-positive
  workflow writes a `rules.Exception` scoped to an exact path, replacing a
  generated SecLang rule containing `ctl:ruleRemoveById`.
- **Reputation crosses as a resolver value.** `ReputationResolver` and friends
  supply gateon-owned signals directly to the engine, so the value never enters
  the request.
- **Protocol enforcement moved out of the engine** into `waf_protocol.go`, which
  is where the gRPC and CORS workarounds stop being necessary.
- **gateon writes its own audit log**, since gwaf writes nothing anywhere.
  Header redaction is code, not a SecLang rule an operator could delete.

## Consequences

### What improved

- gRPC request bodies are inspected. gwaf extracts printable runs from binary
  payloads, so the compat directives and `GRPCMode` are deleted rather than
  reimplemented.
- The reputation header round-trip and the six-header strip are gone: a class of
  header-injection defence was deleted rather than maintained.
- Response inspection is bounded. It previously accumulated the entire upstream
  response in memory; it now buffers to an explicit ceiling
  (`ResponseBodyLimit`, default 1 MiB) and streams past it.
- Fail-open is now a stated policy (`FailOpen`) with a per-tier default. Under
  Coraza an inspection error fell through to the next handler, so the gateway
  failed open silently and nothing recorded that it had.
- The anomaly score is read from `tx.Score()` rather than an unchecked type
  assertion into a transaction variable collection.

### What was lost, and where it went

Every retired rule is recorded in `internal/security/waf/retired.go` with its
disposition and a reason, and `TestEverySeededRuleIsAccountedFor` fails if a
rule is in neither the corpus nor that table.

| Lost | Disposition |
| --- | --- |
| CRS 911/920 method and framing enforcement | `waf_protocol.go` |
| CRS 1120011 header-name length | `waf_protocol.go` |
| CRS 1120012 duplicate Content-Length | `waf_protocol.go` (Go joins the values, so the check is for a comma) |
| Per-IP DoS collections (`initcol`) | Existing rate-limit middleware; gwaf holds no cross-request state |
| Reputation-adaptive body limits (`ctl:requestBodyLimit`) | `Policy.ThresholdFor`; gwaf's limits are per-engine |
| CRS scanner/session-fixation breadth | Reduced. gwaf ships one scanner rule against CRS's lists |
| CRS `RESPONSE-95x` DLP families | Eight gateon DLP rules cover the leak classes that matter; CRS had more |
| CRS auto-update | Retired. `PerformUpdate` returns an error rather than reporting a success that did nothing |

### Behaviour changes an operator will notice

- Three rules moved above the default paranoia level because they are genuinely
  false-positive-prone: generic command injection, SpEL injection, NoSQL
  operators, HTML tag injection and the SQLi tautology check are PL2; the
  ransomware-keyword upload rule and the automated-client rule are PL3. At PL1
  they no longer fire. The originals blocked at PL1.
- `custom_directives` and any SecLang rule are no longer executed. Both log a
  warning naming what to do.
- A response-body rule can no longer change the status code once headers are on
  the wire past the buffer ceiling; it truncates instead.

## Risks

gwaf v0.1.0 is a young dependency: it was tagged from a tree with same-day
commits, and its own attack-simulation coverage was moving quickly at the time
of writing. Two mitigations are in place. `gwaf_contract_test.go` pins every API
gateon uses, so upstream drift breaks the build rather than the gateway. The
attack corpus in `ruleset_test.go` asserts that each converted rule fires on a
payload its SecLang original would have caught, and a benign corpus asserts the
inverse.

Roll out with `AuditOnly` (detection-only) first and compare block rates against
the previous release before enforcing.
