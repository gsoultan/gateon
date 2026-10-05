# 59. A request the gateway let through is not evidence against its client

Date: 2026-10-04

## Status

Accepted. `sec` drives with `ux` co-signing: it changes what can get a client
refused on every route, and what an operator's detection-only controls do.
`data` co-signs migration 69; `qa` the tests.

## Context

ADR 0055 made one predicate, `SecurityThreat.HeldAgainstSource`, decide
whether a threat counts against its source, and marked the WAF's audit-only
and below-threshold matches `Observed`. It listed, as found and not changed,
the same shape everywhere else a control records a finding and lets the
request through. Reproduced through the real middlewares, the real threat
pipeline and the real reputation blocker:

- **The recognisers.** `xss`, `sqli` and `threat_recognition` match
  substrings (`<img`, `update `, `--`, `casino`) and pass the request on.
  Each match took half its score (50, 60, 70) off the client's reputation, so
  the fourth matching request -- the third for the threat recogniser -- was
  refused by the reputation blocker, on that route and every other. All three
  run on the management plane, where a dashboard save whose JSON holds `--`
  matches.
- **Body entropy** took `(entropy - threshold) * 20` off on every compressed
  or encrypted upload: the third was refused.
- **Behavioural profiling** runs after the response and recorded a probe, a
  run of 404s, a steady rhythm or a jump to `/admin` as a penalty: three stale
  links to `/.env` and the client was refused.
- **A device posture change** -- a browser update, a second device -- was held
  against the new fingerprint.
- **The WASM host's `record_threat`** took the guest's score as given: one
  call with 1e9 zeroed the client's reputation. It also filed the threat under
  the peer address with its port and under the route named by
  `X-Gateon-Route-ID`, a header the client writes.
- **The analysis engine** recorded its per-address finding on every pass,
  held, so the same requests cost the address reputation again each pass.
- **File security** filed every refusal as `malware` at 90, "file too large"
  and "type not allowed" included. `AttackEvidenceWeight` counts malware as
  three WAF blocks towards a fingerprint block and an address shun, and after
  the third oversized photo the user was refused everywhere.
- **Brute-force counting** in `anomaly.go` read every POST answered 401 or 403
  as a refused credential attempt, including those the geofence, the WAF, a
  trap, bot management, deception and TLS binding refused before any
  credential was checked.
- **The analysis engine read stored threats**, where `Observed` and
  `Unattributed` were not persisted, and counted every mitigated one as a WAF
  hit -- refusals of an earlier shun, rate limits, geofence blocks, and, since
  `Mitigated` on read includes "the address is shunned now", every detection
  from an address shunned since.

## Decision

**A control that lets the request through records `Observed`.** The
recognisers, body entropy, behavioural profiling, device posture, a WASM
guest's threat and the analysis engine's own findings are recorded, counted,
listed, alerted on and shipped like any other threat, and held against nobody
(ADR 0055's meaning). `kind.Threat` carries the flag for the middlewares that
record through it. Nothing not held against its source is attack evidence
(`AttackEvidenceWeight` is 0), and it no longer adds to the per-address score
the alerting manager's autonomous shun reads.

**A WASM guest cannot refuse**, so everything it records is observed. If the
host ever gives a guest a way to refuse, a threat recorded for a request it
refused is the one that may count. Its score is clamped to 0..100 (NaN to 0),
its source is the address the gateway resolved, and its route is the one the
middleware is attached to.

**File security splits refusals by what they say.** Too large and a type the
route does not take are `file_upload_refused` in the `filesecurity` category,
scored as a rate-limit refusal (10), and are no attack evidence. A signature or
ClamAV finding, an executable disguised as an image and a body the multipart
parser cannot read (a parser differential is how a part is smuggled past the
scan) stay `malware`.

**A refused credential attempt is one the authentication path refused.** A
401 or 403 counts towards brute force when the request reached its service --
the backend's answer, which the gateway cannot read into -- or when the
gateway's own authentication marked it (`request.RefusalAuthentication`):
every refusal an authentication middleware writes other than of a token it
verified (ADR 0031 keeps those out), the forward-auth service refusing, and
the management sign-in refusing a password or a second-factor code. Either way
the request must still look like an attempt (a POST, or a password in
`Authorization`). Any other gateway layer's 401 or 403 checked no credential
and is not counted. The router's service boundary (`request.ServiceBoundary`)
is what marks "reached its service"; the trace records the authentication
mark as `refusal: "authentication"`, which the analysis engine counts as an
attempt.

**Migration 69 persists `observed` and `unattributed`** on `security_threats`,
so a stored threat answers `HeldAgainstSource` as the live one did; rows
written before it get what their type says (every `waf_detected` and the
detection-only types without a refusal are observed, every `data_exposure`
unattributed). The analysis engine counts a stored threat only when it is
attack evidence held against its source, a hit when the request path refused
it when it recorded it (`RefusedWhenRecorded`), a warning otherwise. This
supersedes ADR 0055's "Observed is not persisted".

No new tunable.

## Consequences

- A client is refused by reputation only for requests the gateway refused, as
  ADR 0055 intended; the soft signals these controls fed the WAF's adaptive
  threshold and proof-of-work through reputation are gone. An operator who
  wants to act on a match uses a control that refuses.
- A WASM plugin that used `record_threat` to get clients blocked no longer
  can. Alert rules keyed on the threat types keep firing.
- An address the analysis engine reports is one the request path refused on
  attack evidence, or whose traffic the engine's own trace analysis flags; an
  address refused for policy (rate limit, geofence, bot) is no longer a "WAF
  violator".
- Brute-force detection no longer counts a 401 or 403 a gateway layer other
  than authentication wrote: the WAF, a trap, the geofence, bot management,
  deception, TLS binding, an HMAC signature check. Nor, on the management
  plane, a signed-in user's wrong current password when changing it or
  setting up 2FA; those have the account lockout.

### Found, not changed

- The analysis engine's trace-side counts (`credentialAttempt`,
  `PostAuthFailures`) read `TraceRecord.Refusal`, which the metrics middleware
  copies from `RequestState.Refused`. A geofence or WAF 403 on a POST leaves no
  mark there, so it still counts on that side. Recording the trace's refusal
  from `RequestState.CredentialChecked` is one line in
  `internal/middleware/standard.go`, owned by another change this round.
- A DLP block of a response replaces the backend's answer with 403 after the
  request reached its service, so a POST whose response leaked a card number
  counts as a credential refusal.

## Related

ADR 0025 (attack evidence), 0031 (refusal marks), 0044, 0045, 0055.
