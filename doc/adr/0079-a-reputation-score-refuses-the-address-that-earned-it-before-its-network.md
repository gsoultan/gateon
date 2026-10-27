# 79. A reputation score refuses the address that earned it before its network

Date: 2026-10-26

## Status

Accepted. Driver `sec`, Challenger `perf`. Narrows the reach of a refusal
ADR 0011 and 0024 set, without moving a trust boundary: the identity a score
is kept for is unchanged, and so is who may lower it.

## Context

A reputation score is kept for a browser class on a network -- the JA4 on a
/24 or /64 (`repid.For`, ADR 0011, 0024) -- so that an attacker who changes
address inside their network keeps their record, and so that one attacker on
a stock browser does not take every user of that browser down everywhere.
The reputation blocker refuses the identity on every route once its score
falls below 2, the rate limiter tightens its limit by the score, and proof of
work, the tarpit and the deception response read it too.

A WAF block costs half its score, 50, and the penalty grows with the
violation count, so two blocks took an identity to zero. The identity is
also an office NAT, a campus, a CGNAT pool or a VPN exit: on any of those it
is every client of one browser build, and one of them tripping a WAF rule
twice -- a search for `' OR 1` typed into a form is enough -- refused all of
them on every route for hours. `TestReputationScopeSeparatesNetworksNotUsers`
documented the behaviour and asked for the expectation to be changed
deliberately rather than discovered later. This is that change, found by
auditing the reputation and coordinated-attack controls for false positives
under heavy legitimate traffic.

The same audit found that the violation count, which raises every later
penalty and slows recovery, reset only once `LastEvent` was a day old; and
recovery, which runs on every request after an hour's quiet, moves
`LastEvent`. An identity with traffic every hour -- any shared network --
therefore never reset. A day after its last violation it still paid for it,
and a week after, more, until any single block zeroed its score for good.

## Decision

**A score names the addresses that lowered it, and refuses the network only
once more than one has.** `Reputation` keeps at most two offending
addresses, which is all the rule asks: with one, the score applies to that
address alone and every other client of the class on the network reads the
neutral score; with two, or with a score that names none, it applies to
everyone on the network, as before. A score lowered through gossip, or by
a caller with no address, names none. The count resets a day after the last
violation, keyed on when the score last fell, not on when it last recovered;
the offenders lapse with it.

Every control that refuses, delays, challenges or limits a request on its
score reads it through `ReputationScoreOf` / `ReputationOf`, which apply the
rule to the request's resolved address. The dashboard, the metrics and the
worst-reputations list read the identity's own score, so the network's
record is still visible and still released as one.

**What does not change.** The identity and who lowers it: a threat still
lowers the class's score on the network, the fingerprint block and the
correlation engine still key on the same identity, and an attacker who
rotates addresses within their network is refused from the second address
on. An attacker on one address is refused exactly as before. The cost on
the request path is one string comparison, paid only on a cache hit, which
only a penalised identity has.

**Rejected: estimating the population behind the identity.** Refusing the
network only when the offenders are a small share of the addresses presenting
the class there would need every request to record its address against the
identity -- a write on the pass-through path for every client, to size a set
the attacker fills. The fingerprint block (ADR 0026) bounds its blast radius
the same way this does, by counting offenders, not bystanders.

## Consequences

- A client that trips the WAF twice behind a shared address is refused; its
  neighbours are not. Two such clients on one network are refused together.
- A shared network that keeps sending traffic recovers its violation count a
  day after its last violation, as a quiet one always did.
- A gossiped score still refuses the whole network on the receiving node: the
  sync payload carries no addresses. Adding them is a proto change
  (`ReputationSyncPayload`) for a later change; until then a cluster is as
  wide as before, and no wider.
- `TestReputationScopeSeparatesNetworksNotUsers` now documents both halves of
  the rule.
