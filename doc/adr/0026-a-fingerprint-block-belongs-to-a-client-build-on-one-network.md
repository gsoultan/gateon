# 26. A fingerprint block belongs to a client build on one network

Date: 2026-09-28

## Status

Accepted. Co-signed `arch` ↔ `sec`: it moves the boundary the fingerprint
block acts on -- whom one block reaches, and what a blocked client can do to
step outside it. Extends ADR 0011 and ADR 0024 to the one enforcement site
ADR 0024 listed as still keyed on the whole JA4+, and shares ADR 0025's
definition of attack evidence.

## Context

`UserMitigation` sits on every entrypoint and every route and refuses a
request whose fingerprint is blocked. The block was stored under, and looked
up by, the whole JA4+ (`rs.JA4Plus`), with no network. A JA4+ names a client
build -- a TLS stack and the shape of its headers -- not a client (ADR 0011).
So a block on one reached every user of that browser build, on every network.

How a block was earned made that worse. `escalateMitigation` counted, per
JA4+, every threat that came back `blocked`, `challenged` or `shunned`, or
scored 80, and blocked the JA4+ at the third, as long as the threats had come
from four addresses or fewer. The count never lapsed: three incidents a week
apart were a block, and once past three, every later one renewed it on its
own. And "blocked" included decisions that say nothing about what a client
did -- a rate-limit rejection, a geo or bot-policy block, a reputation block
that follows an earlier decision -- so three rate-limit rejections of one user
behind an office egress blocked that office's browser build, everywhere, for
an hour. The four-address ceiling counted the addresses that produced
threats, not the bystanders a block would reach.

And it missed the client it was for. The per-request bits of JA4H -- the
method, whether a cookie or a referer was sent -- are part of the JA4+, so a
blocked client that dropped its `Referer` presented a new, unblocked key
(ADR 0024's finding, which `UserMitigation` had not followed).

The Playwright suite demonstrated the blast radius for months: every spec
drives one Node HTTP client, one JA4+, so the spec that earned a block 403'd
every spec after it, and each spec that trips the WAF has to release the
fingerprint by hand.

Evidence, all failing against the code before this change:
`TestAFingerprintBlockStaysOnTheNetworkThatEarnedIt` (bystanders on three
other networks refused), `TestDroppingARefererDoesNotShedAFingerprintBlock`,
`TestPolicyRefusalsDoNotBlockAClientBuild` (rate-limit, bot, geo and
reputation refusals each blocked the build) in
`internal/middleware/security/identity`, and
`TestAddMitigationBlocksAFingerprintOnANetworkOnly` and
`TestTheBlockFixRefusesABareFingerprint` in `internal/api` (an operator's
"block" on a bare fingerprint, and the automatic fix on an impossible-travel
finding, blocked a build everywhere).

## Options considered

1. **Keep the class key, raise the threshold.** Fewer blocks, each still
   reaching every network, and still shed by a header toggle.
2. **Remove the fingerprint block.** The reputation blocker already refuses a
   class on a network once its score falls below 2. But its score lives in
   memory, decays on its own, and is not listed or released as a block; the
   fingerprint block is persisted, survives a restart, is shown on the
   mitigation list and released there. The two answer different questions.
3. **Scope it like reputation.** Chosen; see below.
4. **Block the address.** That is `IPMitigation`, which already exists, and
   an address can front an office.

## Decision

**One key, both sides.** A block is stored under, and enforced against,
`repid.For(fingerprint, address)`: the part of the fingerprint a client
cannot vary per request (ADR 0024 -- the JA4 with TLS, the masked JA4H
without) and the client's /24 or /64 (ADR 0011). `UserMitigation` reads it
through `telemetry.GetReputationID`, the identity the reputation blocker
behind it reads, and the recording path builds it with the same function from
the threat's fingerprint and address. `MarkUserMitigated` refuses a key with
no network and `IsUserMitigated` never enforces one (`repid.Scoped`), so a
caller that passes a bare fingerprint fails loudly instead of writing a block
that names a build everywhere.

**Only attack evidence, and only when it repeats.** The automatic block
counts only threats `telemetry.AttackEvidenceWeight` calls evidence -- a WAF
block on a payload, a trap sprung, a malware upload, a brute-force or
exploit-scan detection: the definition ADR 0025's harm rule and Graph
Intelligence use, moved to `telemetry` so there is one. It needs three pieces
from one class on one network within ten minutes (`mitigationEvidenceWindow`),
from four addresses or fewer. The count starts again when the window lapses.
The one-hour TTL (`GATEON_JA4_MITIGATION_TTL`) and the three-piece threshold
(`GATEON_JA4_MITIGATE_AFTER`) are unchanged; no new tunable.

*Why not one blocked threat.* A block on a class and a network refuses every
user of that browser build on that network -- an office, a campus /24, a
mobile carrier's pool -- for an hour. One WAF false positive, a user pasting
code into a support form, would take that office's Chrome users offline, and
a single request carries no corroboration: the WAF has already refused it,
and declining to also block the build costs a rule evaluation on the next
request, not a breach. An attack produces its blocked requests within seconds
or minutes, so three in ten minutes costs an attacker nothing; three
unrelated mistakes spread over a day never add up. What remains is a user who
retries a misjudged form three times inside ten minutes: that can still block
their build on their network for an hour, and only for WAF rules the operator
enforces.

**Releases name what the operator sees.**

- Allow on a row of the user mitigation list sends the row's key -- one class
  on one network -- and releases exactly that.
- Remove Mitigation with a fingerprint (the threat views, the API, the
  Playwright suite's teardowns) names a class, and releases it on every
  network it is blocked on (`ReleaseUserMitigationClass`, a prefix match on
  the key), and holds the class there for the day, as releasing a fingerprint
  did when a block was the class everywhere. A legacy client's JA4 and JA4H
  sent apart name the same class.
- Releasing an address releases the blocks of the fingerprints seen from it,
  on its network.

**Manual blocks name a network.** Add Mitigation takes
`fingerprint|address` (or `fingerprint|network` as the list writes it) and
blocks that build on that address's /24 or /64. A bare fingerprint is refused
with that instruction. The automatic "block" fix on a finding whose source is
a fingerprint (impossible travel reports one) is refused the same way; the
addresses the finding names remain blockable.

**Blocks written before this change are released, not migrated.** They were
keyed on a bare JA4+ and never recorded a network, so moving one would mean
guessing a network, or re-deriving it from threat history and re-blocking on
stale evidence. Every block expires within its hour anyway, so this lifts at
most the last hour's blocks early, and a client still attacking re-earns a
scoped block within ten minutes. They are not enforced, not listed and not
counted as mitigations from the upgrade on, and the prune below deletes them
a day later.

## Consequences

- **Collateral stays inside one network**, and within it reaches every client
  of one TLS stack (TLS) or one HTTP shape (plaintext) -- ADR 0024's trade,
  now the same for both refusals keyed on the class.
- **What a determined client can still do** is ADR 0024's list: mint a new JA4
  per ClientHello (a script can; a stock browser does not), or change
  networks. A campaign from five or more addresses of one build in one /24 is
  not blocked as a class; each address stays subject to the WAF, the honeypot,
  the IP block and the reputation blocker.
- **The table is bounded.** Scoping adds a row per class and network. Rows
  past both the TTL and the release hold -- a day -- are pruned with the other
  telemetry retention (`pruneUserMitigations`); the per-key evidence table is
  the existing 10,000-entry LRU; a class release reads at most 10,000 keys.
- **The mitigation list shows what is in force**: rows past their TTL, which
  block nobody, are no longer listed or counted, and a block's source reads
  `t13d1516h2_8daaf6152771_b0da82dd1658|203.0.113`. The Allow dialog names the
  build and the network.
- **Cost, measured** (`BenchmarkUserMitigation`, benchstat, n=10, old and new
  binaries interleaved, Apple M5 Pro): the three refusals every route carries
  are unchanged (249.4 ns → 253.1 ns, p=0.29; 128 B and 6 allocations both).
  `UserMitigation` alone is +42 ns and one allocation, 32 → 80 B: it is now a
  request's first consumer of the scoped identity, which the reputation
  blocker used to build and now finds cached on the request state. A request
  that matches no route pays it without the blocker.
- **Found, not changed**: the escalation to an IP shun beside this one counts
  distinct JA4+ strings behind an address as distinct users, and a JA4+ varies
  per request with the method, cookie and referer bits, so one client can look
  like three users; and it still counts rate-limit, geo, bot-policy and
  reputation refusals, so three browser builds behind one office egress that
  each hit a rate limit shun the office. It needs the class (`repid.Class`),
  the attack-evidence rule and a decision about the office NAT -- a change to
  what shuns an address, not a drive-by in this one.
  Settled by ADR 0029: five attacking classes within ten minutes, attack evidence only.

## Related

- ADR 0011 (network scope) and ADR 0024 (the class a client cannot vary),
  which this applies to the fingerprint block.
- ADR 0025, whose definition of attack evidence the block now shares.
