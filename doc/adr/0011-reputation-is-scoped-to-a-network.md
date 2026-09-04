# 11. A reputation score belongs to a browser on a network, not to a browser

Date: 2026-09-04

## Status

Accepted. Co-signed `arch` ↔ `sec`: it moves the trust boundary the reputation
control acts on.

## Context

`ReputationBlocker` refuses a request with 403 once the client's score falls
below 2.0. It is appended to **every** route's chain unconditionally in
`internal/router/router.go` — not opt-in, not tier-gated — so it is the single
most widely applied refusal in the gateway.

The score it read was keyed on the JA4+ fingerprint.

JA4+ is `JA4 + "_" + JA4H`. `GenerateJA4H` is built from the HTTP method, the
protocol version, whether a `Cookie` header is present, whether a `Referer` is
present, the header count, a mask of which header names appeared, and
`Accept-Language`. `JA4` is the TLS stack, its version and its offered
parameters. Neither half reads an address, a connection, a session or a
credential.

So JA4+ names the *software* making a request. It does not name the party making
it, and it was never capable of doing so. Two different people running the same
Chrome build in the same language, both carrying a cookie, produce the same
JA4+ — as do all the others.

`mem:security` recorded the opposite, and the wording is worth quoting because it
is how the design survived review: *"This allows for precise blocking of
attackers while allowing legitimate users from the same source IP to continue
accessing the service."* Precise **across addresses** — which is true, and is
genuinely what JA4+ is good for. The sentence simply never asked what happens
**within** one fingerprint.

What happens is this. One patient attacker, using an unmodified browser, drives
the shared score to zero. Every other user of that browser version and language
is then refused on every route of the gateway. It needs no volume and nothing
about the traffic has to look unusual; the attacker's entire advantage is looking
**ordinary**, which inverts every assumption the control was built on. It is
simultaneously a mass false positive and one of the cheapest denials of service
available against a Gateon deployment.

The same identity ran the adaptive rate limiter (`GetFingerprintHash` is
`GetJA4Plus`), the proof-of-work difficulty gate, the tarpit's delay and
deception's troll-response threshold. Every one of them was aimed at a browser
build rather than a client.

The inverse failure is just as real and was equally invisible: a client that
varies its headers gets a fresh identity per request, never accumulates a score
at all, and the control is therefore weakest against precisely the client it
exists to catch.

## Decision

A reputation score is recorded under, and enforced against, a **pair**: the
browser class and the client's network.

```
ReputationIDFor(fingerprint, sourceIP) = fingerprint + "|" + networkScope(sourceIP)
```

`networkScope` is the /24 for IPv4 and the /64 for IPv6 — the smallest units an
operator is normally delegated, and so the narrowest scope that still survives a
client legitimately changing address (a phone moving between cells, a DHCP lease
renewing). Narrower and a NAT pool fragments into scores that never accumulate;
wider and one abusive customer of a hosting provider starts taking their
neighbours down again.

Three properties this depends on:

- **One function, both sides.** The recording path (`store.go`) and every
  enforcement site call `ReputationIDFor`. If they ever diverge, every lookup
  misses and returns the neutral 100, and the control reports "clean" while
  checking nothing — a silent failure of exactly the kind this codebase has been
  bitten by before.
- **The class stays recoverable.** The fingerprint is the composite's prefix, so
  cross-address attribution — the real strength of JA4+, and the reason it was
  chosen — is still available as a query over keys sharing a prefix
  (`ReputationClassOf`). What changed is that it is no longer the thing a 403
  hangs on.
- **Unparseable addresses get their own bucket**, not a fallback to the bare
  fingerprint. Falling back would put every client the gateway cannot place into
  the shared class key and restore the original blast radius for the requests
  least able to explain themselves.

The address is resolved through `request.GetClientIP` with the configured trust
setting rather than by reading `X-Forwarded-For` directly, which is what the
fingerprint's own fallback did. Scoping is a security decision, and an identity
the attacker chooses is not an identity: they could otherwise scope their own bad
score onto someone else's network, or mint a clean one per request.

## Consequences

**The blast radius is bounded, not eliminated.** Two clients behind one NAT still
share an identity, because from outside the gateway nothing in the request
distinguishes them. `TestReputationScopeSeparatesNetworksNotUsers` states this
explicitly so it is a documented limit rather than a later discovery. Claiming
otherwise would repeat the overstatement that made the original design look safe.

**An attacker rotating across many networks now accumulates a score per network
rather than one globally.** This is a real reduction in cross-address
attribution, and it is the deliberate half of the trade: attribution that cannot
be wrong about who it punishes is worth more than attribution that reaches
further. Restoring the reach *safely* is a corroboration problem — block on the
class score only when this network has itself contributed a violation — and
belongs with the work consolidating every enforcement path behind
`internal/security/mitigation`'s existing `MinDistinctSignals` rules, which the
reputation blocker, the honeypot's flat 24-hour ban and deception all currently
bypass.

**Cost, measured** (`BenchmarkReputationBlocker`, Apple M5 Pro, n=6):

| | sec/op | B/op | allocs/op |
| :-- | --: | --: | --: |
| before | 62.54n | 32 | 2 |
| after, first consumer on a request | 117.5n | 80 | 3 |
| after, every later consumer | 89.9n | 32 | 2 |

Roughly +55ns and one allocation per request. Two optimisations were required to
get there rather than accept the naive +275%: an allocation-free IPv4 fast path
(`/24` is a substring, so no parse and no format), and memoising the resolved
client address on the request state, which the loopback guard and the identity
build were otherwise each resolving separately. `EffectiveTrustCloudflare` was
also resolving its environment fallback with a `TrimSpace`+`ToLower` on every
call; it is now resolved once, since an environment variable cannot change under
a running process.

The residual allocation is the composite string itself, which has to exist to be
a map key. It is cached on the request state, so only the first of a request's
several reputation consumers pays it.

This is a check made cheaper, not weakened — the ordering `AGENTS.md` requires
when correctness and latency conflict.

**A dead guard was fixed on the way past.** Both the reputation blocker and the
tarpit exempted loopback by comparing the *fingerprint* to `"127.0.0.1"`. The
fingerprint is JA4+ whenever one exists, and one always exists because JA4H needs
no TLS, so the literal address appeared there only on a last-resort fallback and
loopback was in practice not exempt at all. Both now compare the resolved client
address.

**Enforced by a check, not by review.** `make check-invariants` gained a seventh
invariant: `telemetry.GetIPFingerprint` and `telemetry.GetFingerprintHash` must
not be called outside `internal/telemetry`. Nothing in the type system separates
the two identities — both are a `string`, and passing the wrong one compiles,
runs, and silently restores the old blast radius.

The first version of that check allow-listed calls whose argument was named
`repID`, and a negative test defeated it in one line: renaming the producer while
keeping the variable name sailed straight through. A grep cannot follow dataflow,
so it now constrains something it can actually see — where the class identity is
produced, rather than what a variable happens to be called.

Two deliberate exemptions, both documented at the check: the rate limiter's
`PerFingerprint` key function, where grouping every client of one browser into a
shared bucket is an operator's explicit named choice rather than a default nobody
saw; and `internal/api/security_threat_detector.go`, which reads by raw address
and only ever *relaxes* a score.

**One thing found and deliberately not changed.** That detector discounts an
already-computed threat score by up to 50% when reputation exceeds 80, and
`GetReputation` returns the neutral 100 for a client it has never seen — so "I
have never seen you" currently grants the full discount, exactly as "you have
behaved perfectly" would. Tightening it would halve the detector's effective
threshold for every unknown client and re-tune detection on every existing
install. That is a false-positive decision of its own and should be taken
deliberately, not absorbed as a side effect of this one.
