# 80. The database serves the gateway, not its own bookkeeping

Date: 2026-11-02

## Status

Accepted. Driver `data`, Challenger `perf`; `mem` on the budgets and the
cache, `conc` on the audit writer, `arch` on the peer reload. No trust
boundary moves: every decision reads the same rows it read before, the audit
chain is signed under the same lock, and a peer's message still only clears
and re-reads what this node could already read.

## Context

A survey of where the database is hit on `main` at 534c512d found the
request path mostly clean and most of the load coming from the gateway's own
housekeeping. ADR 0066 and 0067 had already taken the dashboard's aggregate
reads off the idle loop and put security threats and audit entries through
an archive before retention deletes them. What was left:

- The enforcement cache in front of `ip_mitigations` held 1,000 answers on
  every tier. A gateway seeing more clients than that in a mitigation epoch
  re-read the database for most of them, every epoch.
- The fingerprint checks read `user_mitigations` by `fingerprint = ? OR
  ja4h = ?`, and only the first half had an index: SQLite planned a scan of
  the table for every check.
- Nothing pruned `ip_mitigations`. Every address ever shunned automatically
  kept its row.
- `path_stats` kept a row per day, host and path the clients asked for. A
  scanner walking random paths grew it by a row a request, and every
  top-paths read and hourly prune paid for every one of them.
- Retention deleted `path_stats`, `domain_stats` and `user_mitigations` by
  one `DELETE` each, holding SQLite's write lock for the whole backlog while
  the telemetry writer's flushes, threats among them, waited behind it.
- Every security threat was logged to `audit_logs` by the same path an
  operator's action takes: one signed `INSERT`, waited for, on the telemetry
  writer goroutine. Whenever the audit table's lock was held, every threat
  waited the busy timeout and the ones behind it were dropped when their
  channel filled -- the attack decided how much of its own record was kept.
- Each of the four stores sized its pool for Postgres whatever the engine:
  at standard, four pools of 25 on a SQLite file that admits one writer, each
  connection with a page cache of up to 8 MiB.
- On Postgres every dashboard read opened a read-only transaction around its
  one statement, two round trips that isolated nothing.
- Every open diagnostics stream computed its own snapshot every five
  seconds, three database reads each, with nothing shared between viewers.
- A peer's invalidation message cleared this node's proxy caches, which were
  rebuilt from registries read from the database once, at start-up. A route,
  service, middleware, entrypoint, TLS option or WAF rule another gateway
  wrote was never served here until a restart, and the message that
  announced it cost a rebuild of the same stale configuration. The comment on
  the publisher said as much.

## Decision

1. **The enforcement cache is sized by profile** (`MitigationCacheEntries`:
   4,000 / 20,000 / 100,000, about 500 bytes an entry with the ARC's ghost
   lists), overridden by `GATEON_TELEMETRY_UNMITIGATED_CACHE_SIZE`. ADR
   0058's rule stands: "not on the block list" never answers for an address
   the cache has not seen, so a block written on another node a moment ago
   is still enforced, and a flood of new addresses still costs a read each.
2. **Migration 71** indexes `user_mitigations(ja4h)` and
   `ip_mitigations(expires_at)`. The shipped migrations are untouched.
3. **Retention deletes in chunks** of 5,000 rows, each its own statement and
   transaction, until a chunk comes back short, at most a million rows a
   table an hour. The writer's flushes run between chunks.
4. **Spent address shuns are pruned**: an automatic or bounded shun that
   lapsed more than `autoShunMemory` ago and a release past `ipReleaseHold`
   are read by nothing. The cutoffs are the ones the shun ladder and the
   release hold already use, so no decision reads differently. An
   operator's block with no end is never touched.
5. **`path_stats` has a daily budget** (`internal/telemetry/pathbudget`): a
   host's first paths each day are kept as themselves up to
   `PathStatsMaxPathsPerHost`, the rest are counted in one `other` row, and
   past `PathStatsMaxRowsPerDay` every new host and path is counted in one
   row. Counts are folded, never dropped, so totals stay right. Like the
   domain labels it never evicts, so a scanner cannot push out the paths an
   operator watches. A restart seeds the day from the rows stored.
6. **System audit entries go through a writer of their own**
   (`audit.LogSystem`): a bounded queue of 4,096, drops counted and warned,
   stored in transactions of up to 256 rows. Signing stays under the
   manager's mutex at the moment of writing, so system and operator entries
   form the one chain they always did; timestamps are held a microsecond
   past the previous entry's so a batch reads back on Postgres in the order
   it was signed. `audit.Stop` stores what is queued, and main now calls it.
7. **SQLite pools hold `SQLiteMaxOpenConns`** (2 / 4 / 8) per store,
   overridden by `GATEON_DB_SQLITE_MAX_OPEN_CONNS`; Postgres keeps
   `DBMaxOpenConns`. Dashboard reads go to the pool on both engines.
8. **Diagnostics streams share one computation** per four-second period;
   streams ticking while it runs wait for it. The one-shot read is not
   served from it, so an operator who has just acted reads the state as it
   is.
9. **A peer's message re-reads the registries it concerns before the caches
   are cleared.** The database-backed registries gain `Reload`, which
   replaces what they hold only once the whole read succeeded; the WAF rule
   store already had one. A reload that fails is logged and the invalidation
   still runs, which is what every message did before.

## Consequences

- Steady-state query load on a busy gateway falls to the reads a decision
  needs, and the write lock on SQLite is held for one chunk or one batch at
  a time. Each change ships a test that fails against the code before it.
- `path_stats` can no longer be grown without bound by a client, at the cost
  that a host with more distinct paths a day than its budget sees the rest
  under `other` in the top-paths table. The budget is a tier default with an
  env override, as every other bound is.
- A system audit entry can be dropped when the writer is 4,096 entries
  behind, counted in `audit.DroppedSystemEntries`; the threat it records is
  stored in `security_threats` regardless. Before this change the threat
  itself was what got dropped.
- A smaller SQLite pool means more lookups wait for a connection under a
  flood of new addresses; the lookup deadline (ADR 0054) serves the request
  either way, as it did. An operator who measures otherwise raises the pool
  with the env var.
- In a cluster, a change made on one gateway is served by the others from the
  moment its message arrives, not from their next restart. A new entrypoint
  still needs its listener started, which no message does; that remains a
  restart on the peer.

## Alternatives considered

- **One writer connection shared across the four stores on SQLite.** Every
  write path would have to be routed through one pool while reads kept
  another; the gain over a small pool per store, now that the two heaviest
  writers batch, did not justify touching every store.
- **Hourly rollups of threats for the dashboard.** ADR 0067 already reads the
  whole-table aggregates once a minute while someone watches and never when
  nobody does; a rollup table would add a write per flush to save a read per
  minute.
- **A periodic reload of the registries** instead of reloading on a peer's
  message. It would converge a node whose Redis subscription dropped, at the
  cost of five reads a period on every node for ever; the message is the
  event, and a dropped subscription is logged.
- **Evicting the oldest paths from the day's budget** instead of folding new
  ones. Eviction lets a scanner displace the paths an operator watches,
  which is why the domain labels do not evict either.
