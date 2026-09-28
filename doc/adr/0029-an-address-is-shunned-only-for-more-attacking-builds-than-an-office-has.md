# 29. An address is shunned only for more attacking client builds than an office has

Date: 2026-09-28

## Status

Accepted. Co-signed `arch` ↔ `sec`: it moves the boundary of the widest
refusal the gateway makes on its own -- which addresses are refused whole --
and `mem` for the bound on the state behind it. Settles the question ADR 0026
recorded as found and not changed, and applies ADR 0024's class and ADR
0025's definition of attack evidence to the escalation from threats to an IP
shun.

## Context

`escalateMitigation` runs for every recorded threat. Besides the fingerprint
block (ADR 0026), it shunned the threat's address -- `MarkIPMitigated`, which
`IPMitigation` enforces with a 403 on every entrypoint and route, and the
kernel's shun map drops when eBPF runs -- once three distinct JA4+ strings
behind the address had a threat that was mitigated, reputation-category or
scored 80. Four things were wrong with how it counted:

- **A JA4+ string is not a user.** It carries the request's method and
  whether a `Cookie` and a `Referer` were sent (ADR 0024), so one browser
  presents several in one session: the page, its form, a first visit. One
  client whose requests the WAF refused, varying only those bits, shunned
  its own address as "three unique malicious users".
- **Any refusal counted.** Rate-limit rejections, geo and bot-policy blocks
  and reputation refusals say nothing about what a client did (ADR 0025,
  0026). Three browser builds behind one office egress that each hit a rate
  limit shunned the office.
- **Nothing lapsed.** The per-address sets were never pruned: three incidents
  a week apart added up, and after the third, every later one could shun on
  its own.
- **The allowlist was not consulted.** `GATEON_MITIGATION_ALLOWLIST` is "never
  mitigated", and an allowlisted scanner was shunned like any other.

Evidence, each failing against the code before this change, in
`internal/telemetry/address_shun_test.go`:
`TestAnOfficeWhoseBrowsersHitARateLimitIsNotShunned`,
`TestAClientVaryingItsHeaderBitsIsOneClass` (TLS and plaintext),
`TestAttackingClassesAtTheThresholdShunTheAddress`,
`TestAFewInfectedMachinesBehindOneAddressAreContainedNotShunned`,
`TestEvidenceOlderThanTheWindowDoesNotCount` and
`TestAnAllowlistedAddressIsNotShunned`.

What raises the stakes is that **the shun does not lapse.** The row holds
until an operator releases it; the kernel entry likewise. Of every decision
the gateway takes automatically it is the widest and the longest-lived, and
the responder's own hard shun is opt-in for that reason
(`internal/security/mitigation`: "a false positive there is the most
damaging"). This one was on by default and needed the weakest evidence.

### The office-NAT question

Several client builds attacking from one address: an attacker, or an office
with a few infected machines? The evidence cannot tell them apart -- both are
a few classes with WAF blocks behind one address. The cost of each mistake
can:

- **Shunning an office by mistake** refuses everyone behind the egress, on
  every route, with no expiry, until an operator finds the row. And it adds
  nothing against the infected machines: the WAF refuses each of their
  attacks, each build that repeats is blocked on the office's network within
  ten minutes (ADR 0026), and the reputation blocker refuses it once its
  score falls. The shun adds only the people who did nothing.
- **Not shunning an attacker running a few tools** leaves each tool to the
  same per-class controls. The shun would have saved evaluating requests the
  WAF refuses anyway.
- **What the per-class controls cannot contain** is a client that presents a
  new class per connection -- ADR 0024's residue, a script choosing its
  ClientHello. Each class earns too little to be blocked by itself, and the
  address is the only thing its requests share. That is the case a shun is
  for.

## Options considered

1. **Fix the counting and keep three.** Three attacking classes is still what
   an office with a few infected machines, or a few builds tripping one
   misjudged rule, produces; the per-class controls already contain them, so
   a shun at three adds only bystanders, permanently.
2. **Count a class only once it has earned a fingerprint block itself** (three
   pieces in ten minutes). Spares offices with one-off false positives, but a
   client minting a class per connection never puts three pieces on one
   class, so it would never be shunned: the shun would be kept for exactly
   the cases the other controls already answer.
3. **Remove the automatic shun**, leaving it to operators, the opt-in
   responder and the opt-in anomaly detector. Leaves ADR 0024's residue with
   no answer by default.
4. **Make the automatic shun lapse**, as the fingerprint block's hour does.
   It lowers the price of every mistake, but `ip_mitigations` has no expiry and
   the kernel's shun map no sweeper: a schema change and a kernel change,
   recorded below as a follow-up rather than folded into this one.
5. **Count classes with attack evidence in a window, and put the bar above
   "a few".** Chosen.

## Decision

- **What counts** is a threat `AttackEvidenceWeight` calls evidence -- a WAF
  block on a payload, a trap sprung, a malware upload, a brute-force or
  exploit-scan detection -- that passes the existing entry guard. Rate-limit,
  geo, bot-policy, reputation and mitigation refusals never count.
- **Who** is the class, `repid.Class`: the JA4 with TLS, the JA4H without its
  method, cookie and referer bits without. One client is one class whatever
  its requests say.
- **When**: a class counts for `mitigationEvidenceWindow` -- ten minutes, the
  fingerprint escalation's -- after its latest evidence at the address.
  Evidence is dated by the threat (the time the recording path stamped),
  never later than now, and a piece more than a window older than the newest
  evidence there does not count.
- **How many: five** distinct classes (`ipShunMinClasses`).
  - Above "a few": four builds attacking repeatedly from one address -- the
    office with a few infected machines -- are contained build by build, and
    the address stays up. The test named for it pins the number, because the
    threshold test itself follows the constant.
  - Five is ADR 0026's line between one actor and a population, seen from the
    other side: evidence from five addresses of one build is a population the
    class block declines; five builds attacking from one address within ten
    minutes is more attacking software than a few infected machines run, and
    what a client rotating its ClientHello produces in its first five
    connections.
  - The rotation it answers costs the attacker four classes' worth of requests
    before the shun, every one of which the WAF has already refused.
- **Allowlisted sources are not counted at all.** The table exists only to
  decide a shun, so evidence is not kept against an address while it is
  exempt, for the day it no longer is. The threat itself is still recorded,
  listed, correlated and scored: the allowlist exempts enforcement, never
  observation.
- **Releases**: an operator's release still exempts the address from the
  automatic shun from then on (`IsIPUnmitigated`, unchanged), and now also
  forgets the evidence against it -- ADR 0025's rule for every automatic
  limit -- so nothing gathered before a release counts after it.
- **The state is bounded**: at most 10,000 addresses (`maxEvidenceAddresses`,
  the ARC cap it had), each holding at most five class hashes and times in a
  fixed array -- nothing a client wrote. An address evicted early only loses
  evidence, which can delay a shun but never cause one. Before, each address
  held a map that grew by one entry per distinct JA4+ string, without limit.
- **No new tunable.** The bar is a constant, as it was.

## Consequences

- **An office egress is shunned automatically only when five different
  client builds behind it produce attack evidence within ten minutes.** The
  residue: a WAF rule that misfires on ordinary use of a site, tripped from
  five TLS stacks behind one egress within ten minutes. By then each of those
  builds is already blocked on the office's network for an hour (ADR 0026).
- **A client rotating its TLS stack per connection is shunned at its fifth
  class within ten minutes.** One that rotates slower than that is not, and
  each of its requests still meets the WAF.
- **Traffic that draws only policy refusals** -- rate limits, geo, bot policy
  -- is never shunned by this path, however many builds send it.
- **IPv6 is counted per address, as before.** A client rotating addresses
  within its /64 is not shunned by this path; the honeypot keys its bans on
  the /64 (ADR 0024).
- **The Playwright suite's single Node client** is one class per address, so
  no spec can now shun its own source address by varying its requests.
- **Found, not changed**: the automatic shun, the anomaly detector's and a
  playbook's never lapse, and a release exempts an address from all three
  permanently, where a fingerprint release holds for a day. A lapsing shun is
  option 4 above.

## Related

- ADR 0024 (the class) and ADR 0025 (attack evidence, and releases clearing
  history), which this applies to the address.
- ADR 0026, whose "found, not changed" note this settles, and whose
  fingerprint block is what contains the builds this declines to shun.
