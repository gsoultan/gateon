# 54. A block lookup waits a deadline, not the database

Date: 2026-10-04

## Status

Accepted. `perf` drives; `data` co-signs the queries, the pool share and the
driver behaviour, `sec` the order of the exemption and what a lookup that
cannot finish decides, `conc` the goroutine and its bound.

## Context

The 2026-10-04 review (DP-N1, confirmed on Postgres) found that the block
lookups the request path waits for -- `IsIPMitigated` for every request
IPMitigation sees and every connection a TCP entrypoint accepts,
`IsUserMitigated` for every request with a fingerprint -- ran `QueryRow` with
no context and no deadline. With Postgres frozen (SIGSTOP) a new address
waited past 120 s; so did loopback, an address seen a minute before and every
TCP connection. A 40 s table lock made every new client wait 38 s.

- **Loopback waited** because its exemption was read only after the lookup,
  to keep the exemption off the pass-through path.
- **Known clients waited too**, after a minute or two: ADR 0043 reads a "not
  blocked" answer again once it is one to two epochs old, synchronously, so
  the stall spread from new clients to all of them.
- **A context alone would not have fixed it.** lib/pq, the gateway's Postgres
  driver, answers a cancelled context by sending the server a cancel request
  on a new connection and *going on waiting* for the server's reply on the
  old one. A stopped server never replies; neither does one behind a
  partition. `QueryRowContext` with a deadline returns when the server
  answers, not at the deadline.
- **Every waiting request held a pool connection or waited for one,** so the
  stall was also a pool exhaustion for the telemetry writer and the
  management plane.
- And (dataplane F7, low) a cached *fingerprint block* was read again on every
  request, so a blocked client cost a database round trip per request -- and,
  with the database hung, hung.

## Decision

### Exemptions before I/O

Loopback and `GATEON_MITIGATION_ALLOWLIST` are decided before the database is
asked, in `identity.listRefusal` (IPMitigation, and the TCP accept via
`AddressBlocked`) and in `UserMitigation`: when the cache cannot answer
(`telemetry.IPMitigationFromCache`, `UserMitigationFromCache`), the exemption
is read first, and an exempt client is served without a lookup. It costs a
parse (`httputil.IsLoopback` is `netip.ParseAddr`, no allocation; the
allowlist is an atomic load when empty) and no I/O, so an exempt client never
asks the database and never waits for it.

A request the cache answers -- nearly all of them -- reads the exemption only
when it would be refused, as before. Reading it first on every request was
measured at +23 ns (+29%) on `BenchmarkIPMitigation` and +28 ns on
`BenchmarkUserMitigation/alone`, for no client the cache-first order does not
also exempt without I/O.

### A deadline the driver cannot ignore

Every lookup on the request and accept path goes through
`internal/telemetry/lookupgate`:

- The query runs on a goroutine of its own, under a context that ends at the
  lookup deadline. The caller waits for the answer, the deadline, or its own
  context (the request's -- a client that left stops waiting), whichever comes
  first. On the deadline it is answered `ErrTimeout`, and the lookup is
  decided exactly as ADR 0043 decides a failed one: **served, unless this
  node's cache already holds a block; never cached.** It is counted in
  `gateon_mitigation_lookup_errors_total{kind, reason="timeout"}`.
- The deadline is `TierDefaults.BlockLookupTimeout` -- **200 ms minimal, 100
  ms standard, 50 ms enterprise** -- overridden by
  `GATEON_BLOCK_LOOKUP_TIMEOUT` (a Go duration). A healthy point read takes a
  millisecond or two; the minimal tier's small hosts get headroom for
  scheduling, the enterprise tier's request rates less. Zero or garbage is the
  tier's value, not "no deadline".

### One deadline per request

IPMitigation and UserMitigation run at the entrypoint and again at the
route, so a new client makes up to four lookups. Each waiting a deadline of
its own, the first cut made a new client wait four deadlines during a stall
(0.6-0.8 s on the minimal tier, measured). The first lookup a request has to
make sets its budget, one deadline ahead
(`request.RequestState.BlockLookupsUntil`), and every later lookup of the
same request waits only what is left of it; a caller with nothing left starts
no query. The context carrying the budget is built only when the cache has no
answer. A TCP connection makes one lookup and waits its own deadline.

### One query per key, and a bound on all of them

- Concurrent lookups of one key share one query (`lookupgate.Gate`, a
  singleflight). While a query is outstanding -- past its deadline included --
  every lookup of that key joins it, so a hung database is asked once per key,
  not once per request.
- At most **`8 x DBMaxOpenConns`** lookups are in flight at once across
  addresses and fingerprints: **40 minimal, 200 standard, 800 enterprise.** A
  lookup past the bound is **not queued**: it is answered `ErrSaturated` at
  once, decided from the cache or failed open as above, and counted with
  `reason="saturated"`.
- The pool, not the bound, limits what the lookups ask of the database: a
  lookup past the pool waits for a connection inside `database/sql`, and that
  wait honours the deadline. Against a stopped server at most the pool's worth
  of lookups are stuck in a driver read -- each keeps its slot until the
  server answers -- and the rest give up at the deadline and free theirs. The
  bound limits goroutines and the gate's map under a flood of new addresses.
- It is generous on purpose. The first cut was half the pool (2 on minimal);
  on Postgres, a burst of twenty new clients to a *healthy* database then ran
  two lookups and decided eighteen requests without one (`reason="saturated"`
  in the log), which is the fail-open gap below opened by ordinary traffic.
  Eight 1-2 ms reads queued per connection clear well inside the deadline.
- The gate's map holds an entry only while its lookup is in flight, and each
  entry holds a slot, so it never has more entries than the bound. Keys are an
  address (at most 45 bytes) or a fingerprint key `repid.For` builds from a
  computed JA4+ and a /24 or /64 (about 100 bytes): at most ~80 KB of keys at
  enterprise, plus a goroutine each (a few KB of stack).

### A known client never waits

- A "not blocked" answer, and now a fingerprint block, decides requests for
  one to two epochs as before (ADR 0043). From then until **ten epochs**
  (`staleAnswerEpochs`, ~10 minutes) it **still decides the request** and the
  key is read again in the background -- one refresh per key at a time, under
  the same bound (stale-while-revalidate). A refresh that fails or times out
  leaves the old answer; one that is saturated is simply not started.
- Past ten epochs the answer is read before the request is decided, under the
  deadline: a client back after ten minutes has had time to earn a block
  elsewhere, and its first request is the one that should meet it.
- A cached fingerprint block is no longer read on every request (F7). It is
  trusted like a "not blocked" answer, so **a fingerprint block released on
  another node, or one that reached its TTL, ends here within one to two
  minutes** instead of on the next request. A release on this node ends it at
  once, as before (the release override).
- A lookup that read the database before this node wrote a block or a release
  must not leave its answer cached over the write's: the answer can now
  arrive late, from the background. Every block and release write counts
  itself (`blockLookups.writes`) before it touches the cache; a lookup that
  sees the count moved while it ran drops the entry it just cached, and the
  next request reads again.

### Smaller, unchanged on the hit path

The lookup queries are rebound for the dialect once, at store open, instead
of on every read (Postgres's `Rebind` allocates). The cached path -- nearly
every request -- is unchanged: an ARC `Get`, an atomic epoch load, no lock and
no allocation.

## Consequences

Measured on Postgres 17 (a scratch cluster, minimal tier: 200 ms deadline),
the review's reproduction, before and after:

| state | before (79c6c429) | after |
|---|---|---|
| healthy, 20 new addresses at once | p50 81 ms | p50 42 ms, none saturated |
| SIGSTOP: 10 new addresses | all timed out (10 s client limit) | p50 309 ms, all 200 |
| SIGSTOP: an address seen 2.5 min before | timed out | 27 ms |
| SIGSTOP: loopback | timed out | 22 ms |
| SIGSTOP: TCP entrypoint echo (loopback) | timed out | 12 ms |
| SIGSTOP: an address shunned in the database | 403 (cached) | 403 (cached), 20 ms |
| 40 s `ACCESS EXCLUSIVE` lock: 10 new addresses | all timed out | p50 230 ms, all 200 |

- With the database hung, a new client waits at most the deadline, once (its
  later requests join the outstanding query and are answered at once); a
  client seen in the last ten minutes, loopback and the allowlist do not wait
  at all; blocks this node holds stay enforced.
- **The gap ADR 0043 accepted grows by the saturated case.** Under a flood of
  new addresses past the bound -- or a database too slow to keep up -- a block
  this node has not seen since it started is not enforced for the request
  that could not be looked up, as during an outage. An attacker rotating
  addresses can produce that burst. Refusing instead would be the denial of
  service ADR 0043 rejected, now reachable by load alone; queuing would be the
  stall this ADR removes. The narrowing that remains open is warming the cache
  with the blocks in force at start-up, which would close the "not seen since
  start" half for blocks written before the restart.
- `gateon_mitigation_lookup_errors_total` gains a `reason` label (`error`,
  `timeout`, `saturated`). A query summing by `kind` is unchanged; an alert on
  the series without `reason` matches all three.
- `IsIPMitigated` and `IsUserMitigated` keep their signatures and wait at most
  the deadline; `IsIPMitigatedContext` and `IsUserMitigatedContext` take the
  request's context. The detectors and diagnostics that call the old names
  off the request path get the same deadline.

## Alternatives considered

- **`QueryRowContext` with a deadline, and nothing else.** lib/pq waits for
  the server's reply to its cancel request, so against a stopped or
  partitioned server it does not return at the deadline: the review's own
  reproduction would still hang. It is used -- the query does carry the
  deadline, which ends it where the driver can -- but the caller does not rely
  on it.
- **Switch the driver to pgx**, which closes the connection on a cancelled
  context. A driver change across every store for one path, and the bound and
  the singleflight would still be needed against a slow (not hung) database.
- **Bound the lookups at half the pool**, leaving the rest to the telemetry
  writer and the management plane. Measured: it saturated on ordinary bursts
  and decided them without the block list. Against a lock on the table the
  lookups now take the whole pool for at most a deadline each; the writer is
  off the request path and waits that long for a connection.
- **Queue lookups past the bound**, waiting up to the deadline for a slot.
  Every request past the bound would then wait the deadline during an outage,
  which is the stall in a smaller size.
- **A circuit breaker** that stops asking after N timeouts. The bound already
  stops new queries against a frozen database (the slots stay held); against a
  database that times out cleanly each new key costs one deadline, which the
  breaker would trade for a period of enforcing nothing new.
- **A clock-based TTL for the stale window.** Same cost as ADR 0043 measured
  (+86% on the cached lookup); the epoch counts it for an atomic load.
