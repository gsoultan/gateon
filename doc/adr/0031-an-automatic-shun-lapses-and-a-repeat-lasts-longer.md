# 31. An automatic shun lapses, and a repeat lasts longer

Date: 2026-09-28

## Status

Accepted. Co-signed `arch` ↔ `sec`: it changes how long the widest refusal the
gateway makes on its own lasts, and what an operator's release means. `data`
for migration 66, `mem` for the kernel lease table. Settles what ADR 0029
recorded as found and not changed, and records two related decisions taken
with it: allowlisted sources no longer move the shared reputation score, and
the gateway's own token refusals are not credential attempts.

## Context

Five paths shun an address automatically: the address shun of ADR 0029, the
anomaly detector (brute force, exploit scanning), an alert playbook's "block",
the alerting manager's autonomous mitigation, and the incident responder's
opt-in hard shun. Every one of them held until an operator released it, and a
release exempted the address from all of them for good. A fingerprint block
lasts an hour and its release holds a day. A shun refuses everyone behind the
address -- an office egress, a campus, a carrier's NAT pool -- on every route,
and with eBPF in the kernel.

A sixth path was found while tracing the kernel's shun map: `DecreaseReputation`
pushed an address to the kernel once the score kept under the bare address fell
below 20 -- the key `repid.For` uses for a threat with no fingerprint, the
anomaly detector's findings among them. That shun was recorded nowhere: not
listed, not releasable from the list, ignoring the allowlist and releases, and
never lapsing until the process restarted.

"Renew while attacks continue" has a trap. A shunned address is refused before
any detector sees what it sends -- by the kernel with eBPF, by `IPMitigation`
without -- so its attacks cannot be observed while it is shunned. Worse, without
eBPF the refusal is a 403 that the Metrics middleware around `IPMitigation`
records, and a POST refused 403 counted as a refused credential attempt in both
brute-force detectors. A shunned office whose users kept submitting forms fed
the anomaly detector with the shun's own refusals, and a lapsing shun would have
been renewed the moment it lapsed, by nothing the address did.

## Decision

**Every automatic shun lapses, through one function.** `telemetry.ShunAutomatically`
is the only way an automatic path shuns: all five call it (the responder through
`automaticShun` in `cmd/gateon`). The reputation-driven kernel shun is removed:
the detectors that feed bare-address scores already choose between shunning and
throttling under ADR 0025's harm rules, and a second, invisible escalation of
their findings is exactly the never-lapsing shun this removes.

**The ladder.** The first shun lasts 15 minutes. An address shunned again within
24 hours of its last shun lapsing is shunned for twice as long as that one
lasted, up to 24 hours: 15m, 30m, 1h, 2h, 4h, 8h, 16h, 24h. After a clean day it
starts again at 15 minutes. The state is the row itself (`mitigated_at`,
`expires_at`), so it survives a restart and is shared by every path.

- *15 minutes* because a mistaken shun refuses everyone behind the address, and
  the cost that matters is the office that did nothing: a quarter of an hour, not
  however long an operator takes to find the row. It is the honeypot's first
  rung, and longer than the ten-minute evidence window, so the evidence that
  earned a shun has aged out when it lapses and a new shun needs new evidence.
- *Doubling* because a lapse costs a persistent attacker almost nothing to
  survive but costs the gateway almost nothing to answer: the WAF refuses the
  handful of requests an attacker needs to be shunned again (five attacking
  builds for the address shun). Each repeat halves how often that happens.
- *A day* because past it an address is about as likely to have been handed to
  someone else -- dynamic residential ranges, carrier NAT, cloud instances -- as
  to be the same client; it is the honeypot's top rung and the fingerprint
  release's hold. An attacker that keeps coming back is shunned about 24 hours
  in every 24 and a few minutes.

**Renewal is real.** A repeat while a shun is in force changes nothing -- not the
end, not the rung: whatever produced it (threats queued before the shun, a second
detector reading the same attack) is not new behaviour. A shun is earned again
only by evidence recorded after it lapsed: the address shun forgets its evidence
when it shuns, and the anomaly detector's counts are per check interval. And the
shun's own refusals are marked on the request (`request.RefusalMitigation`,
set by `IPMitigation`, and by `UserMitigation` and the reputation blocker, whose
refusals are the same shape), so neither brute-force detector counts them.

**Enforcement reads the end.** `IsIPMitigated` treats a lapsed shun as lifted
from the moment it lapses, with nothing sweeping the row: the enforcement cache
keeps when a shun ends (`shunUntil`), not merely that there is one, and an
address with no shun -- nearly every request -- is answered without reading a
clock. The list and the counts show only shuns in force, and an automatic one
carries `expires_at`, which the dashboard already counts down to ("lifts in
42m"), as it does for kernel throttles; its recommendation says it lifts on its
own and that a repeat lasts longer. No dashboard code changed.

**The kernel follows.** The eBPF Holder leases each shun it puts in the kernel
(`ShunIPUntil`); `ExpireLeases`, the adaptive-limit sweep renamed, lifts lapsed
ones every 30 seconds. The table is bounded as the limits' is: a lease is taken
only after the kernel accepted the entry, so by the shun maps' capacity (10240
addresses, 10240 IPv6 /64s). Two shuns on one /64 share one kernel entry, which
holds for the later lease; an operator's block holds it until released.

**A release holds for a day.** An operator's release lifts the shun, forgets the
evidence (ADR 0029), resets the ladder, and keeps every automatic path off the
address for 24 hours (`IsIPUnmitigated`), as a fingerprint release does. It used
to be permanent. A permanent exemption made sense while a mistaken shun lasted
forever; now a mistaken shun costs 15 minutes, and a permanent exemption instead
protects whoever holds the address next week, or the same attacker back next
month. The tool for "never" is `GATEON_MITIGATION_ALLOWLIST`.

**An operator's block is unchanged.** `MarkIPMitigated` -- Mitigate on a threat,
an applied recommendation -- holds until released, and no automatic shun
shortens it: the automatic write is conditional in SQL on the row not holding a
shun in force or a release inside its hold, so a read-then-write race cannot
override either. An optional duration for manual blocks was not added: it needs a
field on `MitigateThreatRequest`, a proto change this round did not take.

**Migration 66** adds `ip_mitigations.expires_at` (nullable). A row written
before it by an automatic path -- recognised by the reasons those paths wrote,
a frozen list -- gets the expiry it would have had: 15 minutes after it was
written, so nearly all of them lapse at the upgrade. They were earned under the
rules ADR 0029 replaced (three JA4+ strings, rate-limit refusals counted), and an
address still attacking earns a new shun within minutes; ADR 0026 released
pre-scoping fingerprint blocks by the same reasoning. An operator's block keeps
no expiry. Times are bound as UTC strings, not left to `CURRENT_TIMESTAMP`, which
Postgres writes in the server's zone into a column without one.

## Related decisions in the same change

### Allowlisted sources do not move the shared reputation score

The 2026-09-05 allowlist decision kept an allowlisted source's score as
"observation", and a test pinned it. That was right while a score belonged to
one client. Since ADR 0024 it belongs to a client class on a network, and the
reputation blocker refuses every client of the class there once it falls: an
allowlisted scanner's threats refused its neighbours running the same build.
The score is an enforcement input, so the allowlist exempts it. Both writers --
the store's recording path and the incident responder's penalty for every
participant, which checked only the incident's main source -- go through
`telemetry.DecreaseReputationOf`. The threats are still recorded, listed and
correlated. `TestAnAllowlistedSourceDoesNotLowerItsNetworksScore` and
`TestTheResponderDoesNotPenaliseAnAllowlistedParticipant` failed before this;
the pinning test, `TestAllowlistExemptsEnforcementNotObservation`, now drives the
real recording path and asserts both halves, with the reason it changed.

### The gateway's own token refusals are not credential attempts

ADR 0029's residue: a POST refused 401 or 403 counted as a credential attempt
whatever it carried, so a GraphQL, gRPC-Web or Connect client polling with an
expired session -- the dashboard's own tab -- read as password guessing to both
detectors. Each middleware that verifies a presented token -- the management
session check (`PasetoAuth`) and the data-plane PASETO, JWT, API key and OAuth2
introspection middlewares -- marks the request (`request.RefusalToken`) when its
own verification refuses a token that was presented: invalid, expired, revoked,
unverifiable or short of the route's scopes. Not when none was presented, not in
dry run, and never from a header's presence. The Metrics middleware hands the
mark to the aggregator and to the trace (`TraceRecord.Refusal`), and neither
detector counts a marked refusal.

A password-stuffing POST to `/v1/login` that adds `Authorization: Bearer x` still
counts: the login path does not verify the header, so nothing marks it. Basic
over GET still counts. HMAC request signatures and ForwardAuth are not marked --
a signature is not a token the gateway issued, and ForwardAuth's refusal is the
external service's. **Residue:** a backend's own 401 to a POST still counts; the
gateway did not check that credential and cannot say what it was. Guessing API
keys over POST is no longer counted by the brute-force detectors (the price ADR
0029 named); each guess still meets the key check.

Tests that failed before: `TestTheGatewaysOwnTokenRefusalIsNotACredentialAttempt`
(`internal/middleware`, through the real Metrics and auth middlewares, with the
login-stuffing, Basic, backend, no-token and dry-run cases that must still
count), `TestAnExpiredSessionConnectPollerIsNotBruteForce` (`internal/telemetry`)
and `TestAnExpiredSessionConnectPollerIsNotReportedAsBruteForce`
(`internal/api`).

Measured (benchstat, n=10, old and new test binaries interleaved, Apple M5 Pro):
`BenchmarkRecordPerRequest` shows no difference in any case (p ≥ 0.24), 0 B and
0 allocations before and after, including a POST refused 401 carrying request
state; the traced infrastructure chain (`BenchmarkInfraChain_TraceAll`) 547.1 ns
→ 541.0 ns (p = 0.74), 818 B and 14 allocations unchanged. The marked path
(`BenchmarkRecordPerRequestTokenRefusal`) is 255 ns with no allocation.

## Consequences

- **A mistaken automatic shun costs 15 minutes**, and one the evidence keeps
  earning grows to a day. Every automatic shun is listed with when it lifts.
- **Tests that failed against the code before this change**:
  `TestAnAutomaticShunLapses` and `TestAReleaseHoldsForADayNotForever`
  (`internal/telemetry`, SQLite and Postgres), and
  `TestAShunsOwnRefusalsAreNotCredentialAttempts` (`internal/middleware`). The
  ladder, the conditional write, the kernel leases, the migration and the list
  are pinned by `TestTheShunLadder`,
  `TestAnAddressShunnedAgainSoonAfterItLapsesIsShunnedLonger`,
  `TestTheAutomaticWriteCannotOverwriteABlockOrARelease`,
  `TestALapsedShunLeavesTheKernel`,
  `TestLegacyAutomaticShunsLapseAndOperatorBlocksHold` and
  `TestAnAutomaticShunIsListedWithWhenItLifts`; each was mutation-checked.
- **The request path costs the same.** `IPMitigation` asks `IsIPMitigated` on
  every request; its cache now holds an end rather than a flag. Measured
  (benchstat, n=10, interleaved, Apple M5 Pro): the three refusals every route
  carries (`BenchmarkUserMitigation/enforcement-chain`, `IPMitigation` first)
  253.8 ns → 255.9 ns (p = 0.25), 128 B and 6 allocations unchanged;
  `UserMitigation` alone 97.3 → 97.1 ns (p = 0.53).
- **The kernel lags the request path by up to the sweep interval** (30 s): a
  lapsed shun is refused by nobody at L7 at once, and leaves the kernel's map at
  the next sweep. An IPv6 /64's kernel entry holds for its longest shun.
- **A shunned address's refused requests still count as failed requests** in
  the per-IP detector's scan rule, which can throttle it (a five-minute kernel
  lease, ADR 0025); only the credential rule ignores them.
- **A node's cache does not see another node's shun or release** until the entry
  is evicted, as before; the end it caches is the writer's.
- **Legacy rows on Postgres** were written from a zoned time into a column without
  one, so their `mitigated_at` may be off by the server's offset; their expiry is
  computed from the stored value and is consistent with it.
- **No new tunable.** The rungs are constants, as ADR 0029's threshold is.

## Related

- ADR 0029, whose "found, not changed" notes this settles.
- ADR 0025 (a limit only for harm, lapsing when the findings stop) and ADR 0026
  (the fingerprint block's hour and its release's day), which this matches.
