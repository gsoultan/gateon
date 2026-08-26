# 9. Authenticated HA heartbeats and gossip

Date: 2026-08-26

## Status

Accepted.

> Numbered 0009 rather than 0008 to avoid colliding with an ADR being drafted
> concurrently on response-inspection encoding.

## Context

`internal/ha` advertises Active-Passive failover. A node periodically broadcast
an eight-byte datagram to `224.0.0.18:8946` and to `255.255.255.255:8946`:

```
[0:4] virtual_router_id  uint32
[4:8] priority           uint32
```

`listenLoop` accepted any datagram of at least eight bytes, checked only that
the VRID matched, and — if the claimed priority exceeded the local one — called
`releaseVIPs()`, removing the virtual IP from the interface.

There was **no authentication of any kind**. `HaConfig.auth_pass`, the field
whose entire purpose in VRRP is to authenticate advertisements, existed in the
proto and the dashboard and was **never read by the implementation**.

So any host that could send UDP to port 8946 — over the multicast group, the
broadcast address, or unicast — could make the master release its virtual IP
with a single forged packet. Virtual router IDs are small integers and are
trivially enumerable; worse, `sendAdvert` broadcast to `255.255.255.255`, so an
attacker could simply observe the VRID rather than guess it. Repeating the
packet keeps the cluster from ever holding the VIP: a sustained outage of
whatever the VIP fronts, caused by eight bytes. An attacker able to answer ARP
for the freed address turns that into interception.

This is the same shape as the `xdp_geofencing` switch removed in ADR 0007 — a
security control wired to nothing — but the consequence is an unauthenticated
remote off switch on the feature whose only purpose is availability. An operator
who had set `auth_pass` had every reason to believe the cluster was
authenticated.

Exposure was bounded: HA defaults to disabled and is gated in the supervisor, so
only deployments that explicitly enabled it were affected.

## Decision

**Adverts are authenticated with HMAC-SHA256 over a timestamped body.**

```
[0:4]   vrid      uint32
[4:8]   priority  uint32
[8:16]  sent      uint64  Unix nanoseconds
[16:48] mac       HMAC-SHA256 over [0:16], keyed with auth_pass
```

The packet is fixed-length, so truncation is unambiguous rather than parsing as
a short-but-valid advert. Verification uses `hmac.Equal`, because a byte-wise
comparison would leak the expected tag to anyone able to time the response.

**The timestamp is inside the MAC'd region, and adverts outside a replay window
are rejected.** A MAC authenticates the sender but not the moment. Without a
window, an attacker who captured one advert from the highest-priority node could
replay it indefinitely, suppressing failover after that node was genuinely gone
— turning a fix into a subtler version of the same outage. The window is
`max(10s, 3 × advert_int)`: scaled so a slow cluster does not reject its own
traffic, with a floor that tolerates ordinary NTP-level skew. It is symmetric,
because a packet stamped in the future is as suspect as a stale one.

**HA refuses to start when `auth_pass` is empty.** Running unauthenticated is
precisely the defect; starting anyway would preserve it for every operator who
never noticed the field. Failing closed costs HA until a secret is configured.
Failing open costs the virtual IP to whoever asks for it first.

**Rejected adverts increment a counter rather than writing a log line.** An
attacker controls the arrival rate, so per-packet logging would make the fix a
log-flood amplifier. `DroppedAdverts()` is the signal to alert on.

## Consequences

- **HA stops working on upgrade for any deployment that did not set
  `auth_pass`.** This is a deliberate, breaking, fail-closed change and must lead
  the release notes: set `ha.auth_pass` to the same value on every node before
  upgrading. The node logs an error naming the field and the reason.
- Nodes running mismatched versions will not agree: the old format is eight
  unauthenticated bytes and the new one is a 48-byte signed packet, so an
  upgraded node rejects a legacy peer's adverts as malformed. **HA clusters must
  be upgraded together**, and during a rolling upgrade both halves may claim the
  VIP. Draining the passive node first avoids that.
- `auth_pass` is now load-bearing, so it is a secret: it must not appear in logs
  or in exported configuration.
- The wire format is not VRRP and never was — the original code says as much
  (`"VRRP uses 224.0.0.18, but we use a simpler UDP port for ease of
  deployment"`). It does not interoperate with keepalived, and this change moves
  it further from the standard. The README's "Active-Passive failover (VRRP)"
  claim should say "VRRP-style"; that is a separate docs change.

## The same defect in the gossip transport

`InitGossip` created memberlist with **no `SecretKey`** — no encryption, no
authentication. `ReputationDelegate.NotifyMsg` JSON-decodes whatever arrives and
calls `ApplyRemoteReputation(fingerprint, score, ...)`, and
`internal/middleware/reputation.go` shuns any client scoring below 2.0. So any
host that could reach port 7946 could pick which addresses this gateway refuses
— a customer, a CDN egress range, a partner — or raise its own score to bypass
reputation shunning, proof-of-work and the deception layer, which all read it.

Two further fields were inert:

- **`enable_gossip` was never read.** Gossip keyed off `HaConfig.Enabled`, so
  enabling VIP failover silently opened a port that has nothing to do with
  failover.
- **`gossip_bind_addr`, `gossip_bind_port` and `gossip_peers` were never read.**
  The port was hardcoded to 7946 and **`Join` was never called**, so configured
  peers were never contacted. Since nothing joined outward, the only members were
  hosts that connected inward. The advertised peer sync had never worked; the
  port reliably did nothing but accept strangers.

Now: `SecretKey` is SHA-256 of `auth_pass` (memberlist wants exactly 16/24/32
bytes, and hashing avoids both truncating a long passphrase and padding a short
one into looking stronger than it is); `enable_gossip` gates the transport;
the bind address, port and peers are honoured; and gossip refuses to start
without a secret, for the same fail-closed reason as the heartbeat.

Peers are joined once rather than on a retry loop. That is the ordinary
memberlist pattern — the cluster converges as soon as any node reaches any
other, so a node that boots early is picked up when a peer starts and joins
inward — and a retry loop would need a lifecycle `InitGossip` does not have, it
being boot-only with no stop hook. An unsupervised goroutine is worse than the
gap it closes.

### Additional consequences

- **Gossip stops for anyone who had HA on but never set `enable_gossip`.**
  Given it had never actually clustered, this removes an open port rather than a
  working feature.
- `auth_pass` now protects both the heartbeat and the gossip cluster, so it must
  match across every node, and mismatched nodes will simply not see each other.

## Not addressed

The equal-priority tie-break still resolves by accepting whichever peer already
claims master (`// For simplicity here` in the original). With authentication in
place this is no longer a security question, but two same-priority nodes can
still both defer, so neither takes the VIP. Fixing it means implementing the
documented higher-IP-wins rule and is an election-correctness change, not a
security one — it wants its own change and its own tests.
