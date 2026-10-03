# 55. A penalty lands only on the client that did the thing, and only for evidence

Date: 2026-10-04

## Status

Accepted. `sec` co-signs with `ux`: it changes whom the gateway refuses on its
own, and what the dashboard tells an operator audit-only and DLP do. `arch` for
the identity the correlation engine groups by (it moves the boundary of who an
incident's response reaches).

## Context

The 2026-10-04 truth review found three ways an innocent client was refused on
every route, each reproduced on the built gateway with real traffic:

- **TRUTH-NEW-1 (default-exposed).** The correlation engine grouped signals by
  fingerprint. A fingerprint names a browser build, not a client (ADR 0011,
  0024), so one audit-only detection against a user on 203.0.113.0/24 and an
  attacker's three SQL injection attempts from 198.18.5.5, both running stock
  Chrome, made one "critical incident" whose source was the user. The responder
  penalised every participant's network, and a bystander on the user's /24 who
  sent nothing got 403. With no attacker the same detection left the bystander
  at 200. Feed refusals (`ip_mitigation`) were correlation signals too, against
  ADR 0044's "never evidence towards an escalation".
- **TRUTH-NEW-2.** An audit-only WAF -- "Record matched rules and block nothing
  on this route", the documented rollout step -- lowered the client's
  reputation by 50 on every match. The third request with a false positive was
  refused, on that route and every other.
- **TRUTH-NEW-3.** A DLP finding in a *response* was filed as a WAF block
  against the client that read it, in block, redact and audit mode alike. The
  third view of a redacted receipt was a reputation block on every route.

Looking for the same three shapes in every place a threat is recorded against a
client found four more:

- Every WAF match the WAF did not refuse cost 50, in enforcing mode too: a
  match scored below the route's threshold, and the inbound data-leak corpus,
  which logs a secret someone pasted and by design never refuses. A user pasting
  an example key into two support tickets was refused everywhere.
- An audit-only WAF still refused on its fast-path checks (malformed token,
  header and body entropy, client consistency). Only the protocol check
  honoured audit-only.
- A refusal of an earlier decision fed itself. The reputation blocker records
  its refusal with a score of 100 minus the reputation, and every threat took
  half its score off the client's, so each refused retry pushed the score back
  to zero: a client refused by mistake stayed refused for as long as it kept
  trying. The refusals were correlation signals too (`signal_types=
  reputation_block,waf_detected` in the review's logs).
- A playbook whose action is "block" shunned the source of any threat it
  matched, including all of the above.

## Decision

**One predicate decides whether a threat counts against its source:**
`SecurityThreat.HeldAgainstSource`. A threat that is not held against its
source is recorded, counted, listed, broadcast and shipped to a SIEM like any
other, and acts on nobody: it moves no reputation, is no evidence towards a
fingerprint block or an address shun, is not a correlation signal, and does not
trigger a playbook's block or the alerting manager's autonomous shun. Three
kinds are not held against their source:

- **Unattributed** (unchanged meaning, ADR 0024): the client did not choose to
  send it -- a cross-site trap load, loopback, and now a leak in a response.
- **Observed** (new, not persisted): a control matched and did not act -- an
  audit-only WAF, or a WAF match the engine scored below the route's blocking
  threshold, including the log-only inbound data-leak rules. ADR 0025 already
  called the WAF's detection-only matches "not evidence" for escalation; they
  are now not evidence anywhere.
- **A refusal of an earlier decision**: `ip_mitigation` (a shun or a feed
  listing), `user_mitigation` (a fingerprint block), `ip_shunning`,
  `reputation_block`. It is the gateway's own decision coming back.

Serving a challenge already records no threat (ADR 0045); a *wrong answer* to
one still does, and is still held against its sender.

**Correlation groups by the identity a penalty lands on.** The engine keys a
signal by `repid.For(fingerprint, address)` -- the client class on a /24 or /64,
or the address alone when there is no fingerprint -- the identity reputation is
kept for. A signal with no address is not correlated. A browser build seen on
two networks is two sources; an incident can no longer span networks, so its
response cannot reach a network that did not take part. The responder
penalises the incident's source class on the source's network **once** (it used
to penalise every participant, which within one network took the same score
down once per address). An incident handed over with participants on other
networks still penalises only the source's: a cross-network browser-class match
is context, never a reason to act. Nothing records that context yet; the
incident's fingerprint is the query.

**Audit-only means audit-only.** The WAF records every match it does not refuse
as `waf_detected` and observed. The fast-path checks record an observed
`detected` finding and let the request through when the WAF is audit-only. The
would-block counter is unchanged and still counts what enforcement would refuse.
The route editor says detections never count against the client.

**A response-phase finding is about the server's data.** It is recorded as a
`data_exposure` event on the route: no source address, no fingerprint,
unattributed, with the action taken on the response (`blocked`, `redacted` --
a new value, not a mitigating action -- or `detected` for DLP audit), and the
address it was served to in its details for a leak investigation. It no longer
counts towards the per-address WAF-block tally the exploit-scan detector shuns
on, and the WAF no longer puts the reader under an adaptive eBPF rate limit. It
is no longer counted as a WAF block in the security funnel, which a served
page never belonged in.

**No migration.** `Observed` is not persisted, like `Unattributed`: the type
(`waf_detected`, `data_exposure`) says it in a stored row. No new tunable.

## Consequences

- A client is refused by reputation only for what it sent and the gateway
  refused, or for an incident built from its own network's refusals.
- Correlated incidents are per class per network. A botnet sharing one build
  across a hundred networks is a hundred sources; each still meets the WAF, the
  per-network fingerprint block (ADR 0026) and the address shun (ADR 0029).
- An operator relying on audit-only detections or below-threshold matches to
  tighten the WAF's adaptive threshold or proof-of-work through reputation loses
  that; enforcing mode is the way to act on matches.
- The Security Hub lists DLP findings as `data_exposure` with no source; alert
  rules keyed on `waf_blocked` for DLP need the new type.
- A client already refused stops re-earning penalties by retrying, so a
  mistaken score recovers at its normal rate.

### Found, not changed (same shape, outside this decision)

- Detection-only middlewares still lower reputation by half their score: the
  threat recognition middleware (`xss_detected` 50, `sqli_detected` 60,
  `generic_attack`/`php_vulnerability`/... 70, including on the management
  plane), body entropy (`high_entropy_payload`), the WASM host's
  `record_threat` (score chosen by the plugin, unbounded), behavioural
  profiling (`behavioral_anomaly`, `api_fuzzing`, `probe_detected`,
  `dga_detected`), device posture changes and the analysis engine's per-minute
  re-recordings. Each is `detected`/`flagged`, never refused. Whether a
  detection-only control may lower a score the reputation blocker refuses on is
  a decision of its own: the answer that matches this ADR is "no" (mark them
  `Observed`), at the price of the soft-signal tightening they feed today.
- The analysis engine reads stored threats, where `Unattributed` and
  `Observed` are not persisted, and counts every mitigated one -- refusals of
  earlier decisions included -- as a WAF hit for its address. Its own harm rule
  uses `AttackEvidenceWeight`, which excludes them, so it does not shun on them.
- The file-security middleware files "file too large" and "type not allowed"
  as `malware`, which `AttackEvidenceWeight` counts three times.
- `anomaly.go`'s brute-force count includes POSTs refused 403 by the geofence,
  the WAF, a honeypot ban, bot management, deception and TLS binding.

## Related

- ADR 0011, 0024 (the identity), 0025 (attack evidence), 0026 (the fingerprint
  block), 0029 (the address shun), 0031 (allowlisted sources and the shared
  score), 0044 (feed refusals are not evidence), 0045 (serving a challenge is
  not evidence).
