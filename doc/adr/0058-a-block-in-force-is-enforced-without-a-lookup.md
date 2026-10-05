# 58. A block in force is enforced without a lookup, and an IPv6 client is its /64

Date: 2026-10-04

## Status

Accepted. `sec` drives (what a lookup that cannot finish still refuses, whose
address a block covers, whose header names an identity); `mem` co-signs the
bound on the block list, `data` migration 68 and the list's queries, `perf`
the request path, `conc` the refresher and the list's writers. Narrows the
gap ADR 0043 accepted and ADR 0054 widened; settles dataplane F5 and F10
from the 2026-10-04 review.

## Context

Three findings, each a way an attacker chose whether a block applied to it.

- **The saturation gap (ADR 0054's residue).** A lookup that cannot finish --
  the lookup gate saturated, the database slow, stopped or partitioned -- is
  decided as ADR 0043 decides a failed one: served, unless this node's cache
  already holds the block. The cache learns a block only by looking it up,
  one key at a time, and holds 1,000 answers by default. So after a restart
  every block was unknown until its first lookup, and an attacker with many
  addresses, by making the lookups saturate, was served past its own block.
  ADR 0054 named the narrowing: warm the cache with the blocks in force.
- **DP-F5: IPv6 per /128.** The automatic shun counted its evidence per
  address and the block list was read per address, while the kernel's shun
  map, the per-address connection caps and the honeypot key an IPv6 client by
  its /64. A subscriber is delegated a /64 and picks the low 64 bits itself,
  so one host rotating through it put every attacking build on a fresh key
  and was never shunned; an operator's block of one of its addresses it left
  by picking another. With eBPF on, the kernel dropped the whole /64 for the
  same block: one gateway enforced two different things.
- **DP-F10: the reputation identity from X-Forwarded-For.** With no JA4 and
  no JA4H, `GetIPFingerprint` returned the leftmost `X-Forwarded-For`, read
  raw, as the class half of `GetReputationID`. A client could shed a bad score
  per request, or spend it on another, by naming it. The branch was not
  reachable while `GenerateJA4H` always answers -- which is why no test saw
  it -- but it was the only place an identity was read from a header the
  client writes.

## Decision

### Every block in force is read into a list, and enforced from it

`internal/telemetry/blocklist` holds every address shun and every
fingerprint block in force, with when each ends. The store reads it at
start-up -- opening the store waits for the first read, at most 5 s, outside
the store lock -- and again every minute (the epoch a cached answer is
trusted for, so a block or release written on another node reaches the list
when it reaches the cache). This node's own blocks and releases are written
into it the moment they are written to the database, so a read that began
before them cannot undo them.

The request path consults the list only where the cache cannot answer: on a
miss, and under a stale "not blocked" answer (ADR 0054's stale window). A
block the list holds is refused **with no lookup**, whether or not one could
run; nothing about it counts as a failed or saturated lookup. The answer
nearly every request gets -- a fresh cached answer -- is unchanged, and an
empty list costs an atomic load. Readers never lock: the list is an
immutable view behind an atomic pointer, replaced whole by its writers, which
serialise among themselves.

**Addresses not on the list keep ADR 0043 and 0054 exactly**: looked up under
the deadline, one query per key, a bounded number in flight, and a lookup
that cannot finish decides its request served. The list does not answer
"not blocked": a block written on another node since the last read is still
found by the lookup, as before.

What each kind holds:

- **Address shuns**: `status = 'mitigated'` and not lapsed, keyed by
  `repid.Address`, with `expires_at` (none: until released). A shun that
  lapses after the read lapses in the list at the same instant -- the end is
  compared on read.
- **Fingerprint blocks**: each scoped key whose latest row inside the TTL is a
  block (a release marker first in a tie, as the lookup orders them), ending
  one TTL after it was written.

### The bound, and a list larger than it

At most **20,000 address shuns and 20,000 fingerprint blocks** (a key of at
most 128 bytes; `repid.For` writes under 100). Measured at the bound: 1.3 MB
for the shuns and 2.8 MB for the blocks with keys of the length `repid.For`
writes (about 3.7 MB with every key at 128 bytes) -- at most 5 MB for one
read, and a refresh holds two reads for a moment. This node's writes since
the last read are bounded at 4,096 per kind.

A list larger than the bound is read **newest first**, and the blocks past it
are enforced as every block was before this list existed: from the cache, or
by a lookup. That keeps the blocks an attack in progress earned and leaves
the oldest -- an operator's block from last month -- to the lookup, which
enforces it whenever the database answers. `gateon_mitigation_block_list_complete{kind}`
is 0 while that is so, `gateon_mitigation_block_list_entries{kind}` says how
many are held, and the first read that is cut short logs it. A write of this
node's past its 4,096 is left to the cache and the lookup in the same way;
a release past it is applied to the list itself, and a read begun before it
is discarded, so a release is never undone.

Not a tunable: it bounds an attack's worth of blocks, not a size an operator
chooses, and every block past it is still enforced when the database answers.

### An IPv6 client is its /64, everywhere a block is kept

`repid.Address` / `repid.AddressKey` are the one keying of an address-level
decision: an IPv4 address as itself (a v4-mapped one unmapped), an IPv6
address as the network address of its /64. The automatic shun's evidence,
every write (automatic shun, operator block, bounded block, release), every
read (the cache, the lookup, the list, the release hold) and the threat
list's shun status go through it. The stored key is a plain address
(`2001:db8:1:2::`), so a row the dashboard lists can be released and pushed
to the kernel as it is. On the request path the cache keys IPv6 by the
`netip.Addr` of the /64: a parse, and no allocation beyond the one the
cache's interface key already cost.

**A manual block of one IPv6 address blocks its /64.** The host behind it
chooses its address and can change it at will (privacy addresses rotate on
their own); the kernel already blocked the /64 for the same block; and
reading both the address and the /64 would double every uncached IPv6 lookup
to keep a block that does not hold its target. The cost is ADR 0011's: a
provider that puts several customers in one /64 has them blocked together.
The allowlist is still read for the address that asks, so an allowlisted
address inside a blocked /64 is served, and the block event closes the open
L4 sessions of the whole /64 except allowlisted ones.

**Migration 68** moves each IPv6 row to its /64's key and each v4-mapped row
to its IPv4 address. Rows of one /64 become one: a block in force over one
that is not (open-ended over bounded, the later end first), then a release,
then the latest written. Without it a block set on one IPv6 address before
the upgrade would be read by nothing.

### An identity is never named by a header the client writes

`GetIPFingerprint` no longer reads `X-Forwarded-For` or `X-Real-IP`. A
request with no fingerprint has no class half, and `repid.For` keys it by the
address the resolver decides (`ClientIPOf`), which believes a forwarding
header only from a trusted proxy (invariant 8). `check-security-invariants.sh`
now refuses a raw read of either header outside `internal/request`, the proxy
and forward auth, which read it to forward it.

## Consequences

- **After a restart**, every block in force is enforced from the first
  request, with the database hung or the lookups saturated, and without a
  lookup. Measured in `TestABlockInForceIsEnforcedAfterARestartWithTheDatabaseHung`
  and `TestABlockInForceIsEnforcedWhileTheLookupsAreSaturated` (SQLite and
  Postgres) and, through the middlewares, `TestBlocksWrittenBeforeARestartAreRefusedWithTheDatabaseHung`.
- **What is still open**: a block written on another node within the last
  minute, and the oldest blocks of a list past the bound, are enforced only by
  a lookup -- so not while the lookups are saturated. And a database that does
  not answer at start-up leaves the list empty until a read succeeds (opening
  the store waits 5 s for it): the list is not persisted on the node.
- **One read a minute** of each block table: the rows in force (by the status
  index for shuns, the TTL for fingerprint blocks), newest first, `LIMIT`
  20,001. An install with no blocks reads two empty results.
- **A fingerprint block or release written on another node** now reaches this
  node's list within a minute, as it reached the cache (ADR 0043); an address
  release on another node now ends the list's block within a minute, where a
  cached shun held until it ended (ADR 0031's note) -- the cache's own entry
  still does, as before.
- **IPv6**: one host rotating through its /64 is shunned at its fifth
  attacking build, as an IPv4 address is; ADR 0029's note that IPv6 is counted
  per address is superseded. The dashboard lists an IPv6 shun as its /64's
  network address. The threat list's "mitigated" filter, which runs in SQL,
  still matches an IPv6 threat only by its own address; the per-threat status
  is read from the list.
- `gateon_mitigation_block_list_entries{kind}` and
  `gateon_mitigation_block_list_complete{kind}` are new; `kind` is `ip` or
  `user`, as in `gateon_mitigation_lookup_errors_total`.

## Alternatives considered

- **Seed the cache (the ARC) at start-up.** It holds 1,000 answers by default
  and evicts under exactly the flood of new addresses that saturates the
  lookups: the seeded blocks would be gone when they were needed.
- **Fail closed when a lookup cannot finish.** ADR 0043 and 0054 rejected it:
  a denial of service any client can trigger by load alone.
- **Answer "not blocked" from a complete list without a lookup.** It would end
  the lookups for every client the list does not name, and with them the
  enforcement of a block written on another node in the last minute. Kept as
  ADR 0043 and 0054 have it.
- **Persist the list on the node** so a restart with the database down
  enforces it too. A file of blocks that outlives releases written while the
  node was down needs its own expiry and invalidation; the database is the
  record, and a node that cannot reach it at start-up is already degraded.
- **Keep a manual IPv6 block exact and read both keys.** Two lookups for every
  uncached IPv6 client, to keep a block its target leaves at will.
