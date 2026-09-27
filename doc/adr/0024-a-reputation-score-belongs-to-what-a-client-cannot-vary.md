# 24. A reputation score belongs to what a client cannot vary per request

Date: 2026-09-27

## Status

Accepted. Amends ADR 0011: it changes which part of the fingerprint the
network-scoped identity is built from. Co-signed `arch` ↔ `sec`: it moves both
edges of the boundary a reputation refusal acts on -- whom one refusal reaches
inside a network, and what a refused client can do to step outside it.

## Context

ADR 0011 made the identity a score is recorded under, and enforced against, a
pair: the JA4+ fingerprint and the client's network (/24, /64).

```
repid.For(fingerprint, sourceIP) = fingerprint + "|" + networkScope(sourceIP)
```

Its context named an "inverse failure" -- a client that varies its headers gets
a fresh identity per request and never accumulates a score -- and its decision
did not address it. JA4+ is `JA4 + "_" + JA4H`, and JA4H is written from the
request: the method, the HTTP version, whether a `Cookie` was sent, whether a
`Referer` was sent, how many of `User-Agent` and `Accept-Language` were sent,
the ALPN, and a hash of which. The first four change from one request to the
next for an ordinary browser -- a page is a GET and its form a POST, a first
visit has no cookie, a typed URL has no referer -- so they change for a client
that wants them to.

`TestTogglingAHeaderDoesNotShedAReputationBlock`
(`internal/middleware/security/identity/reputation_rotation_test.go`) is the
evidence. A client earns a score of zero the way the store records one and is
refused; its next request drops the `Referer`, and its identity goes from
`_ge11nr0200_7e33b58890ac|203.0.113` to `_ge11nn0200_7e33b58890ac|203.0.113` --
a fresh, neutral 100 -- and it gets 200. The same happens when it sends a
cookie or switches to POST, and for a TLS client too, since JA4H is half of its
JA4+. The blocker every route carries was weakest against exactly the client it
exists for. The operator's release had the mirror-image problem:
`ResetReputationClass` compared stored keys with the JA4+ the threat recorded,
so a release named after one request's fingerprint missed the scores the
client's other requests had earned.

## Options considered

1. **The network alone.** Drop the fingerprint and score the /24 or /64. No
   header, TLS offer or anything else a client writes escapes it. But one bad
   client then refuses everyone behind its office egress, CGNAT pool or
   university -- the blast radius ADR 0011 kept the fingerprint to avoid.

2. **Keep JA4+ and consult a network-level score alongside it**, refusing when
   either is below the threshold. Catches every kind of rotation. But once the
   network score is low it refuses the whole network, which is option 1's
   collateral reached more slowly; it costs a second lookup per request and a
   second write per threat, and it needs a threshold and a recovery rate of its
   own -- a new tunable on every install.

3. **The part of the fingerprint a client does not vary per request, on the
   network.** Chosen; see below.

4. **More of the request in the fingerprint** -- the `User-Agent` value, the
   `Accept` values -- to tell clients on one network apart. More precise, and
   every field added is one more the client writes and can toggle.

5. **Leave it.** The WAF still refuses each malicious request on its content.
   But refusing a client's *later* requests is the blocker's whole purpose, and
   it would stay optional for any client that noticed.

## Decision

The class a score is kept for is what the client cannot vary from one request
to the next:

- **With a TLS fingerprint, the JA4 alone.** The TLS stack writes it once per
  connection from the ClientHello; nothing in a request can change it. A stock
  browser presents one JA4 for every request it makes.
- **Without one** -- plaintext, or TLS terminated in front of the gateway by a
  proxy that does not forward a fingerprint -- **the JA4H with the method, the
  cookie flag and the referer flag marked out**: `_ge11cr0200_7e33b58890ac` and
  `_po11nn0200_7e33b58890ac` are both `_--11--0200_7e33b58890ac`. What stays --
  the HTTP version, which of `User-Agent` and `Accept-Language` were sent, and
  the ALPN -- does not change between one browser's requests, and still tells a
  browser from curl or a health checker. A bare JA4H (the rate limiter's `ja4h`
  strategy) gets the same class.
- **Anything else** stays its own class, whole, as before.

```
repid.For(fingerprint, sourceIP) = repid.Class(fingerprint) + "|" + networkScope(sourceIP)
```

Every caller still hands `repid.For` the whole fingerprint and `repid` alone
decides which part counts, so ADR 0011's "one function, both sides" holds
without every caller learning to cut a JA4+: the store's recording path,
`GetReputationID` (the blocker, proof-of-work, deception, the tarpit, the
adaptive rate limiter), the correlation responder's penalty, and the
operator's releases -- `resetReputationForIP` through `repid.For`,
`ResetReputationClass` through `repid.Class` -- agree. `ClassOf(For(fp, ip))`
is `Class(fp)`.

`repid` is a leaf package and cannot import `telemetry`, which writes JA4H, so
it cuts the class by position. `TestReputationIdentityFollowsTheJA4HLayout`
(`internal/telemetry`) builds requests with `GenerateJA4H` and fails if the
layout moves without `repid` following.

## Consequences

**Collateral stays inside one network, and within it a score now belongs to
every client of one TLS stack (TLS) or one HTTP shape (plaintext).** Before, two
people on one /24 running the same browser shared a score only for requests
whose method, cookie and referer bits also matched -- most of an ordinary
session's requests, so the widening is smaller than it sounds; now they share it
for all of them. A different TLS stack, or a plaintext client that is not a
browser, on the same network is not refused
(`TestTheClassStillSeparatesClientSoftware`), and nothing crosses networks
(`TestReputationBlockIsScopedToTheOffendersNetwork`). Behind a TLS-terminating
proxy that does not forward a JA4, every browser on a /24 shares one score: the
plaintext class can tell a browser from curl, not one browser from another.

**What a determined client can still do:**

- **With TLS, change its ClientHello.** Every distinct cipher or extension list
  is a new JA4 and a fresh score. That takes control of the TLS stack -- not a
  stock browser, but trivial for a script (`curl --ciphers`, any TLS library) --
  and the number of identities is unbounded. A browser also presents a
  different JA4 over QUIC than over TCP: two identities, not a lever.
- **Without TLS, toggle whether it sends `User-Agent` and `Accept-Language`**
  (four combinations) **and its HTTP version** (1.0, 1.1, h2c): at most twelve
  identities per network.
- **Change networks**, ADR 0011's accepted trade.

The other controls still act on every request: the WAF, the rate limits, the
honeypot (per address, per /64 for IPv6), the IP mitigation table and the
responder's per-address penalties. Closing the TLS residue needs a signal the
client does not write -- option 2, or corroboration across identities on one
network -- and that is a collateral decision of its own, not taken here.

**Migration.** Scores live in memory. Those recorded before an upgrade are under
keys nothing reads afterwards and age out; the client's next violation is scored
under its class. In a mixed-version cluster, gossip from a node not yet upgraded
arrives under the old keys until it is. The dashboard's reputation list shows
the new keys: `t13d1516h2_8daaf6152771_b0da82dd1658|203.0.113` and
`_--11--0200_7e33b58890ac|203.0.113`.

**Cost, measured** (benchstat, n=10, the old and new test binaries run
interleaved on a host shared with other builds):

| | before | after |
| :-- | --: | --: |
| `BenchmarkReputationBlockerIdentity` tls-ipv4 | 205.9 ns, 112 B, 3 allocs | 173.4 ns (-16%), 80 B, 3 allocs |
| plaintext-ipv4 | 158.4 ns, 80 B, 3 allocs | 161.6 ns (~), 80 B, 3 allocs |
| tls-ipv6 | 340.0 ns, 168 B, 5 allocs | 321.4 ns (~), 152 B, 5 allocs |
| `BenchmarkReputationBlocker` (ADR 0011's) | 167.0 ns | 160.5 ns (~) |
| `BenchmarkReputationBlocker_Cached` | 125.2 ns | 124.4 ns (~) |

No allocation was added on any path; ADR 0011's +55 ns and one allocation are
untouched. A TLS client's key is shorter, which is where the saving comes from.

**Writers and readers that still use keys the blocker never reads.** Found by
walking every `DecreaseReputation`, `GetReputation` and `GetReputationScore`
call; none is in code this change owns, so each is recorded rather than fixed:

- `internal/api/security_threat_detector.go` reads `GetReputation(ip)` for its
  "high trust" discount. A fingerprinted client's score is never under its bare
  address, so a client the blocker refuses at zero still gets the full 50%
  discount -- and the exemption at invariant 8 reasons that scoping would change
  nothing, which is not so.
- `internal/telemetry/anomaly.go` records `brute_force_attempt` and
  `exploit_scan` with an address and no fingerprint, so their penalties land
  under the bare address, which nothing on the request path reads.
- `internal/telemetry/zerotrust.go` (`impossible_travel`,
  `device_posture_change`) and the detector's graph threats record a
  fingerprint and no address, so their penalties land under `Class|?`. The
  device-posture check also compares whole JA4+ strings, which change with the
  method, cookie and referer of each request, so ordinary browsing raises it.
- `internal/middleware/standard.go` (the trace's trust score) reads
  `GetReputation` of the bare JA4+ or the address, and `otel.go` asserts
  `rs.Fingerprint.(string)` on a `*ClientFingerprint` and falls back to the
  address: both report 100 for every fingerprinted client.
- `UserMitigation` enforces a fingerprint mitigation on the whole JA4+, so a
  mitigated client sheds it with the same `Referer` toggle. It cannot simply
  adopt `repid.Class`: its key is not scoped to a network, and the class alone
  would block every user of one TLS stack everywhere. It needs ADR 0011's
  scoping first.

## Related decisions in the same change

- The honeypot keys bans, strikes and its capacity accounting on the /64 for
  IPv6, as ADR 0011 scopes reputation and ADR 0020 the kernel's shuns; IPv4
  stays per address.
- A trap hit that is a cross-site no-cors subresource load is refused and
  recorded, and recorded `Unattributed`: no strike, no ban, no reputation
  penalty, no escalation, no correlation. The request came from the visitor's
  browser, but a page on another site chose to send it.

## Related

- ADR 0011, which this amends.
- ADR 0013, which put `reputation.go` in `identity`.
- ADR 0020, the kernel's /64 keying.
