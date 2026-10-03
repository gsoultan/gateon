# 48. A dashboard number is computed from what runs, or not shown

Date: 2026-10-03

## Status

Accepted. `ux` (what the Security Hub says) co-signs with `obs` (how each
number is counted); `qa` for the gate in decision 6.

## Context

The 2026-10-02 truth review found that the Security Hub's figures, all wrong
on a default install, overstated the gateway's security -- the numbers an
operator reads to decide whether to act:

- **T4** the "Signature engine: 11 rules active" card was hard-coded on
  (`posture.go` set `Enabled: true`). The engine runs only inside a
  `file_security` middleware.
- **T11** the Security Posture percentage was computed in the browser from
  client reputation: 100% with nothing configured, rising as an attacker's
  reputation fell (100 → 93 → 98).
- **T12** an audit-only WAF was shown as "Protecting all routes"; the AI
  Advisory never mentioned audit-only and counted a route whose own audit-only
  WAF had replaced the enforcing global one as covered.
- **T13** the mitigation funnel counted every request twice (65 sent, 130
  shown) and listed IP-filter refusals as "Allowed".
- **T25** a banned client's requests to existing routes produced "unlisted
  route" findings whose automatic fix offered to create those routes.
- **T26** the posture's `waf.autoUpdate` reported a flag that no longer
  updates anything, and the document gave snake_case keys the API never sent.
- **T27** threats from loopback were dropped: behind a local proxy every WAF
  block was invisible.
- **T28** the attack-trend chart was always empty on SQLite.
- **T30** bandwidth-by-IP counted a chunked upload as 256 bytes.
- **T31** "Reputation Status: Good" was a string literal.
- **T38** the configuration gates passed with five inert switches present,
  because they accepted any Go mention of a setting as proof it worked.

## Decision

An operator acts on these numbers, so each is computed from the data it claims
to describe, or it is not shown.

### 1. Posture is computed from configuration, server-side

`internal/security/posture` derives, from the objects the router composes
chains from (routes, middlewares, entrypoints, global config):

- per enabled HTTP route, the **effective WAF mode** -- the route's own `waf`
  middleware's `audit_only` if it has one (with the global value inherited when
  the global WAF is on with CRS and the route leaves it unset, as
  `mergeGlobalWAFDefaults` does), else the global WAF's mode; a route with two
  WAF middlewares blocks if either does;
- per route, whether it runs the **signature engine** (a `file_security`
  middleware with `enable_signature_scan`, default on, parsed as the factory
  parses it);
- the **posture score**:

      percent = round( sum(weight_i * credit_i) )

  | control | weight | credit 1 | credit 0.5 | credit 0 |
  |---|---|---|---|---|
  | WAF | 40 | every route's WAF blocks | (averaged per route) a route that only detects | no WAF |
  | TLS on reachable entrypoints | 20 | every non-loopback, non-UDP entrypoint encrypts or redirects to one that does | (averaged) | plaintext |
  | Management not exposed | 20 | management API only on its restricted listener | that listener is open to any address | public management, or `allowed_hosts` (a Host header the client writes) |
  | Anomaly detection | 10 | on (it shuns) | -- | off |
  | Audit logging | 10 | on, entries signed | on, unsigned | off |

  Traffic, threats and client reputation are not inputs. An attacker's
  activity cannot raise it, or lower it. The report carries every control with
  its weight, credit and a sentence, and the dashboard's tooltip shows the
  formula and the controls.

`GET /v1/security/posture` gains `waf.mode`, `waf.routes`
(`total/enforcing/detecting/unprotected/signatureScanning`),
`signatures.routes` and `score`; `waf.autoUpdate` is replaced by
`customRulesFromDisk`, what the repurposed flag does. The document gives the
real (lowerCamel) keys, and a Go test holds the JSON names to the dashboard's
types.

The AI Advisory uses the same coverage: an audit-only WAF is a finding --
critical when nothing blocks anywhere, a warning when some routes only detect --
and an audit-only route WAF is no longer counted as coverage.

### 2. The dashboard says what the report says

"Detecting only (audit)" wherever the WAF's mode is shown and no route blocks;
"Blocking on N of M routes" when some route's WAF only detects or there is none;
an overview alert when any WAF only detects. The signature engine reads "Not
running" without a scanning route. "Reputation Status: Good" is replaced by the
number of clients whose reputation has been lowered and the lowest score
(`/v1/security/reputations`). "Mitigated in 24h" -- a count since midnight -- is
labelled "Mitigated Today". Every card keeps a loading and an error state.

### 3. The funnel counts each request once, by outcome

The request's Metrics middleware that records the per-request statistics (the
first to finish -- the route's, else the entrypoint's) increments
`gateon_request_outcomes_total{outcome}`: `forwarded` when the router's service
wrapper stamped the request (every route middleware passed it), else `refused`
for a status >= 400 and `answered` otherwise. One fixed label with three
values, pre-resolved: one atomic add per request. The funnel's ingress is the
sum, so `allowed + refused + answered == ingress` by construction. Stages
attribute refusals from the existing counters; what no stage claims (IP and
host filters, limits, no route) is "other refusals", never "allowed". Blocked
sources (`ip_mitigation`, `user_mitigation`) are their own stage, the WAF stage
excludes the blocks restored from earlier runs, server errors are counted over
one scope.

We did not add a counter to every refusing middleware: the outcome is known at
one place every request passes, and the stages remain attribution, not the
baseline.

### 4. Loopback threats are shown and held against nobody

A threat from loopback is recorded as an unattributed threat: listed, counted,
broadcast, and kept out of reputation, escalation and correlation. Loopback is
every local client at once behind a local proxy, and the request path never
refuses it; dropping its threats hid every WAF block in exactly the deployment
that most needs to see them.

### 5. Counts that were wrong at the source

- **Attack trend.** SQLite stores a threat time as Go's text form
  (`2026-10-02 16:39:31.975 +0700 WIB m=+25.1`), which `strftime` cannot read.
  The bucket is cut from the text (`substr(timestamp, 1, 13)`), with one row's
  full timestamp returned so the reader knows its zone. On Postgres a
  `timestamp` without time zone holds the writer's local wall clock; it was
  read as UTC (seven hours off on the review host) and is read as local time
  now. Tested on both engines.
- **Chunked uploads.** A body with no Content-Length is counted as it is read,
  one allocation per such request, shared by the entrypoint's and the route's
  Metrics; a request with a length, or none, costs nothing new.
- **Unlisted routes.** An entrypoint-labelled trace counts as unrouted only if
  it is the 404 that no matching route answers (or predates the status field)
  and carries no refusal mark. Trap paths are still reported.

### 6. The gate checks use, not mention

`scripts/checkconfig` keeps its first question (is each proto `*Config` field
selected?) and adds two:

- **Dead sinks.** A struct field filled from configuration -- a middleware
  config lookup, `BoolFields.Get`, a proto `*Config` read -- must be read
  somewhere other than where it is written. json-tagged fields of the
  management API's response types are exempt (encoding/json reads them). One
  hop, by type information; reflection and the kernel are baselined with a
  note (`sinks-baseline.txt`).
- **Effect registry.** Every key the dashboard's middleware editors write must
  have a row in `internal/middleware/dashboard_key_effects_test.go` -- built
  through the factory the router uses, at two values, against the same probe,
  answers required to differ -- or a line in `effects-baseline.txt`. A row may
  be marked inert with its finding; it then asserts the key is still inert and
  fails the day the fix lands, so the fixer turns it into a proof.

- **Documented values.** A proto string field whose comment lists its values
  (`string action = 6; // "notify", "block", "challenge"`) must have each value
  compared against -- `==`/`!=` with a literal or string constant, or a `case`
  -- in a package that reads the field or is handed it directly; values are
  folded (case, `_`, `-`, `.`, space) as the readers fold them. Open lists
  ("etc."), example values and wire messages are skipped. It flags the alert
  playbook's "Trigger JS Challenge" action, which does what "Notify Only" does
  (`values-baseline.txt`).

`check-security-invariants.sh` check 6 reads keys written through `toggle()`
and across line breaks, which it missed.

### 7. Bot protection is counted where it runs

The global bot-management settings only supply defaults to the
`bot_management` middleware. Coverage (posture `waf.routes.botManagement`, the
advisory's bot insight) counts the routes that carry the middleware; the
global switch is not coverage. The funnel's bot stage counts what bot
management records -- a challenge served in place of the response
(`challenge_served`, `pow_challenge_served`) and the threat pipeline's
`blocked` -- not the `integrity_failed` / `challenge_failed` outcomes nothing
records.

## Consequences

- Proven on this tree: the dead-sink check fails on `XFCCConfig.ForwardBy`
  (T21) and on the pre-fix compress middleware; the registry fails when T8's
  inert mark is removed and on the pre-fix compress middleware; check 6 fails
  on a camelCase key written through `toggle()` that the old check passed.
- It found two inert settings the review had not: the compress middleware's
  `max_buffer_bytes` (fixed: a response declaring a longer body is not
  compressed) and `acme.challenge_type`, which the TLS manager stores and never
  consults -- autocert answers HTTP-01 and TLS-ALPN-01 whatever it says
  (baselined, owner decision pending).
- Limits: the registry matches keys by name, not by middleware type; it sees
  keys written as literals only; global settings have no rows yet, so a global
  setting that is read, used and wrong (T3, T10) is caught by neither new check
  -- only by a behavioural test of its own. 111 dashboard keys start in the
  effects baseline.
- The posture score will read lower than before on most installs, and differ
  by deployment rather than by traffic. That is the point; the upgrade note says
  so.
- Effective WAF mode is derived here from the same configuration rules the WAF
  factory applies. If the WAF package exports an effective-mode function, the
  posture should call it instead.

## Alternatives considered

- **Keep the posture in the browser, with better inputs.** The browser does not
  hold routes, middlewares and entrypoints together, and a SIEM reading the API
  would get no score.
- **Count detection-only as no credit.** An audit-only WAF still records every
  attack; half credit, stated, is more useful than equating it with nothing,
  and the WAF card says "Detecting only" either way.
- **Add a refusal counter to every middleware that refuses.** A dozen owners'
  files, and the next middleware would forget; the outcome is visible at one
  place every request passes.
- **Keep dropping loopback threats and say so.** Behind a local proxy that
  means the Security Hub shows nothing at all; showing them unattributed costs
  no enforcement.
- **A behavioural row for every dashboard key now.** 122 keys; a ratchet with a
  baseline makes new keys pay as they arrive, as `lint-new` does.
