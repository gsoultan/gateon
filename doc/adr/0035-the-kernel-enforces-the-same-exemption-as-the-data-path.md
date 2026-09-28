# 35. The kernel shun map enforces the same exemption as the data path

Date: 2026-09-28

## Status

Accepted. Co-signed `net` ↔ `sec`: it changes what the eBPF data plane drops,
and where the IP mitigation allowlist is enforced. It settles the point ADR 0032
recorded as "still not uniform: the kernel", and applies ADR 0029's one
exemption rule to the last path that ignored it.

## Context

ADR 0029 gave the request path one rule for who is never actively mitigated --
`exemptFromEnforcement`: loopback, and any address in
`GATEON_MITIGATION_ALLOWLIST`, which is documented as a "CIDR/IP list never
mitigated". ADR 0032 extended that rule to every entrypoint: an allowlisted or
loopback address on the IP mitigation list is served by the HTTP path
(`IPMitigation` → `AddressBlocked`) and by every TCP entrypoint (`tcpServer.handle`
→ `AddressBlocked`) alike.

Both ADRs left the same hole, and ADR 0032 named it: **where eBPF runs, the
kernel's shun map ignored the allowlist.** `MarkIPMitigated` -- an operator's
explicit block, and the DDoS mitigation that calls it -- pushed the address into
the kernel shun map with no exemption check, so an allowlisted or loopback
address the operator had also blocked was dropped in the kernel while every
user-space path had already decided to serve it. XDP/TC drops the packet before
any middleware runs, so the kernel had the final and opposite say.

The automatic shun (`ShunAutomatically`, ADR 0031) already exempted before it
wrote anything, so it never reached the kernel with an exempt address. The gap
was the manual/DDoS push and any future caller of the kernel shun.

## Decision

### One rule, one function

The exemption is now a single function, `mitigation.ExemptFromEnforcement(ip)` --
loopback (`httputil.IsLoopback`) or allowlisted (`mitigation.IsAllowlisted`) --
that every path calls:

- the request path, through `identity.exemptFromEnforcement`, which now
  delegates to it (the reputation blocker, the fingerprint block and
  `AddressBlocked`);
- the automatic shun, `ShunAutomatically`, which used to compose the two
  primitives inline;
- and the kernel, below.

One producer of the decision means the three cannot drift -- the failure mode ADR
0029's reputation-identity note warns about, where enforcement and recording key
on rules that have quietly diverged and every lookup silently misses.

### The gate lives at the kernel chokepoint, not the call sites

Every kernel shun in production funnels through one method: the eBPF `Holder`'s
`shun`, shared by `ShunIP` (an operator's block, whose kernel push has no lease
and holds until released, and the DDoS mitigation's direct
`s.EbpfManager.ShunIP`, which is that same `Holder`) and `ShunIPUntil` (the
automatic shun's leased entry). Both `MarkIPMitigated`'s
`container.p.ShunIP` and the diagnostics `s.EbpfManager.ShunIP` reach the kernel
only through it.

So the gate goes there, once, rather than at each call site that reaches it:

- **A future caller cannot bypass it.** A per-site check leaves the next site
  that pushes a shun unguarded -- exactly how ADR 0032's own kernel hole
  survived the entrypoint fix. The chokepoint has no next site.
- **No site duplicates the rule.** The call sites push; the chokepoint decides.
- **Skipping the push is success, not an error.** "Never mitigated" is the
  allowlist's promise, so an exempt address is a no-op that returns `nil`, and
  the leased path takes no lease a sweep would later have to lift.

### The kernel mechanism does not import the policy

The `Holder` reaches the rule through an injected predicate
(`SetExemption(func(ip string) bool)`), wired once at startup to
`mitigation.ExemptFromEnforcement`, rather than `internal/ebpf` importing
`internal/security/mitigation`. The kernel manager is a low-level mechanism; the
allowlist is a security policy; the dependency arrow points from policy to
mechanism, never back. A `Holder` with no predicate installed -- the zero value,
and what a build with no policy leaves -- gates nothing, so the gate is opt-in
and cannot silently swallow a shun on a path that never wired it. The predicate
reads the live allowlist, so wiring it once keeps it current across config
reloads.

### Scope: IP shuns only

The kernel shun map is keyed by address (IPv4) or /64 (IPv6). A **fingerprint**
shun keys on a browser class, not an address, so the IP allowlist does not apply
to it -- and the kernel has no fingerprint shun to gate anyway: it cannot compute
a JA4 from a packet (ADR 0007's `Shunner` note), and the reputation path stopped
pushing a fingerprint-derived kernel shun some time ago. This decision is scoped
to IP shuns, and says so.

### A shun already in the kernel for an address later allowlisted

An operator may allowlist an address that is **already** in the kernel shun map.
This decision **stops adding**, and does not sweep what is already there.
Justification, from cost:

- Every **automatic** kernel shun is leased and lapses within 15 minutes to a
  day (ADR 0031), swept by `ExpireLeases` every 30 s, so it clears itself
  regardless of the allowlist.
- The only lasting case is an operator's **manual** block of an address they
  then allowlist. The HTTP and TCP paths serve it immediately (`AddressBlocked`
  reads the exemption live), and the operator's own **release** of the block
  lifts the kernel entry.
- A sweep would have the policy layer enumerate and mutate the kernel shun maps
  on every allowlist reload -- an O(map) cross-layer scan, for a self-inflicted
  corner case that resolves itself for every automatic shun and by one release
  for the manual one. The scan buys too little to justify crossing the layer to
  run it.

## Consequences

- An allowlisted or loopback address the operator has **also** blocked by hand is
  no longer dropped in the kernel: it is served by every path, kernel included.
  The block **row is still written** -- the allowlist exempts enforcement, not
  the operator's record of their own decision -- so it still lists and can still
  be released.
- No automatic path can put an exempt address in the kernel (`ShunAutomatically`
  exempted already; the chokepoint is a second guard).
- A future caller of `Holder.ShunIP`/`ShunIPUntil` inherits the exemption with no
  action on its part.
- Residual: a manual block placed **before** an address is allowlisted stays in
  the kernel until the operator releases that block. Documented in
  `doc/upgrading.md`.
- No request-path cost: the exemption is read only on the branch a block would
  refuse, and the kernel gate is on the mitigation-write path, not the request
  path. `BenchmarkExemptFromEnforcement` is 15.7 ns / 0 allocs before and after
  the delegation.

## Verification

`internal/ebpf/holder_exemption_test.go` and
`internal/telemetry/kernel_shun_exemption_test.go`, each failing against the
code before this change (with the gate disabled, an allowlisted and a loopback
address reach the kernel):

- `TestHolderDoesNotPushAnExemptAddressToTheKernel` -- allowlisted, loopback v4
  and v6 are not pushed; a non-exempt address is. Uses the real production
  predicate, so it cannot pass while the request path's rule says something else.
- `TestHolderDoesNotLeaseAnExemptAutomaticShun` -- the leased `ShunIPUntil` path
  neither pushes nor leases an exempt address, and does both for a non-exempt one.
- `TestHolderWithNoExemptionPushesEverything` -- a `Holder` with no predicate
  gates nothing (the gate is opt-in).
- `TestAManualBlockOfAnExemptAddressIsNotPushedToTheKernel` -- the manual/DDoS
  record path (`MarkIPMitigated`) routed through the exact production chain
  (adapter → `Holder` with the wired exemption) does not push an allowlisted or
  loopback address, does push a non-exempt one, and records the block either way.

## Related

- ADR 0032, whose "still not uniform: the kernel" this closes.
- ADR 0029 (the one exemption rule) and ADR 0031 (leased, lapsing kernel shuns).
- ADR 0007 (the kernel has no fingerprint shun; XDP/TC read the IP header).
