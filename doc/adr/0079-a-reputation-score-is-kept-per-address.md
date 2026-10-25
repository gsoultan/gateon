# 79. A reputation score is kept per address

Date: 2026-10-25

## Status

Accepted. Amends ADR 0011 and 0024 for the reputation score only. `sec`
co-signs: it moves who a penalty reaches. `perf` for the second key a
fingerprinted request can now build.

## Context

The reputation blocker refuses any score under 2 on every route. Since ADR
0011 and 0024 that score was kept for one browser build on one /24 (or /64):
`repid.For(fingerprint, network)`.

A WAF block costs a score 50, then 100, because the penalty is adaptive. So
two blocks against two different people on one office or carrier network who
ran the same browser took that network's score to 0. On the built gateway, one
of those blocks was the false-positive corpus's own recorded case (a password
with metacharacters) and the other was an SVG upload. After them, all 58
following users on the /24 got `403 Forbidden by Security Policy (Reputation
Block)` on every route. Recovery is about 0.7 points an hour.

ADR 0055 already says a penalty lands only on the client that did the thing.
The score was the one place it still landed on a whole network.

## Decision

**A reputation score is recorded and enforced under `repid.ForAddress`:** the
fingerprint's class on one address. That is an IPv4 address as itself, or an
IPv6 address as its /64 (`repid.AddressKey`, the key the shun and the block
list already use). The /64 is kept for IPv6 because a subscriber controls the
low 64 bits and rotates through them (ADR 0058).

- `telemetry.GetReputationID` and `DecreaseReputationOf` use it, so the
  blocker, proof-of-work, deception, the tarpit and the adaptive rate limit all
  read the score the penalty wrote.
- An operator's release resets the score under the new key.
  `ResetReputationClass` still finds every score of a class by its prefix.

**What a /24 is right for stays on `repid.For`.** That covers the fingerprint
block (ADR 0026), which already requires evidence from several addresses, and
correlation. It also covers the per-fingerprint rate-limit bucket, so a /24
that rotates addresses does not get one budget per address.
`telemetry.GetNetworkClassID` builds and caches that key.

## Considered and rejected

**Keep the /24 and raise the threshold.** That makes the blocker slower for a
real attacker and still refuses the whole network after a few more blocks.

**Penalise only the addresses that contributed to the network's score.** That
is the per-address key with extra bookkeeping.

## Consequences

- An attacker that rotates addresses inside one /24 no longer pulls down a
  score for the whole network. The fingerprint block and the address shun
  still act on that pattern, and they were built for it.
- Scores recorded under the old key before an upgrade are no longer read. They
  age out of the LRU and are not migrated. A client that was being refused
  under the old key is served after the upgrade.
- A request with a fingerprint can build two keys where it built one: the
  score key, and the network key when the fingerprint block runs. Each is built
  once per request and cached on the request state.
- During a rolling upgrade, gossip between old and new peers carries scores
  under different keys, so a score is not shared until every peer is upgraded.
