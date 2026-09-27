# Storage, Retention & Resource Bounds

Gateon keeps operational data in a few complementary stores. This guide documents
where the data lives, how it is bounded, how disk space is reclaimed, and the
environment variables you can tune to control memory and disk usage.

## Persistent stores

| Store | Backend | Holds | Location |
|-------|---------|-------|----------|
| Telemetry SQL | SQLite (default), Postgres | Aggregated path/domain stats, security threats, audit rows | `gateon.db` (SQLite) or the configured DSN |
| Telemetry traces | Pebble (embedded LSM) | Per-request access-log / trace records | `telemetry_pebble/` next to the SQLite DB |
| Trace archive (opt-in) | zstd-compressed NDJSON files | One file per UTC hour of traces, kept after the live store lets them go | `trace_archive/` in the data directory |
| Cache / rate-limit | Redis (optional) | Response cache, distributed rate-limit counters | External Redis |

> SQLite is used out of the box so a single binary is fully self-contained.
> Point the telemetry store at Postgres for multi-node deployments; those
> engines manage their own vacuuming, so the SQLite-specific reclamation below
> becomes a no-op.

## Retention

The telemetry store runs a background prune loop. Retention is configured in days
and can be set globally or per data category:

- Global default: the `retentionDays` passed to `InitPathStatsStore` (config-driven).
- Per category (override the default when > 0):
  - Path & domain stats
  - Access logs (Pebble traces)
  - Security threats
  - Audit logs (only pruned when explicitly enabled)

Categories left at `0` fall back to the global default. The prune loop:

1. Deletes SQL rows older than the cutoff (`path_stats`, `domain_stats`,
   `security_threats`, `audit_logs`).
2. `DeleteRange`s expired Pebble trace keys, then **compacts the pruned key
   range** so the space is physically reclaimed instead of left as tombstones.
3. Reclaims SQLite disk via `PRAGMA incremental_vacuum` (enabled by
   `auto_vacuum=INCREMENTAL`) and `PRAGMA wal_checkpoint(TRUNCATE)` to shrink the
   WAL file.

### Expected disk usage

Disk footprint is dominated by the access-log traces (one Pebble entry per
request, including optional captured headers/bodies). To bound it:

- Lower the access-log retention if you do not need long trace history.
- Disable request/response body capture for high-traffic routes.
- **Sample the traces** with `GATEON_TRACE_SAMPLE_RATE` (see below). This is the
  only one of these that reduces CPU as well as disk.
- For very high request rates, prefer a server-side SQL backend and a dedicated
  volume sized for `requests/day × avg-record-size × retention-days`, plus
  Pebble's transient compaction overhead (≈ one extra copy of the pruned range).

### Trace sampling

`GATEON_TRACE_SAMPLE_RATE` controls how many requests are traced: `1` records
every request, `N` records one in N, `0` records none. It overrides the tier
default.

| Tier | Default | Why |
| :-- | :-- | :-- |
| `minimal` | `0` | The trace store is closed on this tier, so recording built a record and threw it away. |
| `standard` | `1` | Every request, which is what every install already does. |
| `enterprise` | `1` | Every request. |

Recording a trace clones both header maps and writes a Pebble entry. Measured
against the infrastructure chain it is **208 B and 7 allocations per request** on
a chain that otherwise costs 610 B and 7 — so tracing roughly doubles the
allocation count of every proxied request. On a busy standard-tier deployment,
lowering the rate is the single largest saving available without turning a
feature off.

**Failed requests are always traced, whatever the rate.** Anything that returned
4xx or 5xx is recorded in full even at `N=100`. Sampling assumes the requests are
interchangeable, which is true of the successful ones and false of the rest:
people open the trace view because something went wrong, and a sampled view of
failures is worse than no sampling at all, because it still looks complete while
missing the request being searched for. 4xx is included alongside 5xx
deliberately — a 403 is what a WAF false positive looks like from outside.

`0` means zero, including failures. It is an explicit opt-out, and on `minimal`
it reflects a tier chosen for its memory ceiling.

A malformed value falls back to `1` rather than `0`: a typo must not silently
switch tracing off, because that is discovered during an incident.

## Trace archive

The live trace store keeps traces for the access-log retention — seven days on
the standard profile. The trace archive keeps them after that. Each closed hour
of traces is copied into one compressed file, and the live store may not delete
an hour until the archive holds everything the store has for it.

The archive is **off on every profile**: turning it on writes to a disk every
existing install has budgeted for something else. Turn it on in
**Settings → Trace archive**, or with `GATEON_TRACE_ARCHIVE_ENABLED=true`.

### Where the files are and what they are called

```
<data dir>/trace_archive/
└── 2026/
    └── 09/
        └── 26/
            ├── traces-2026-09-26T00Z.ndjson.zst
            ├── …
            └── traces-2026-09-26T14Z.ndjson.zst   ← requests that started 14:00–15:00 UTC, 26 Sep 2026
```

- **One file per hour, named for the hour it holds:**
  `traces-YYYY-MM-DDTHHZ.ndjson.zst`. The `Z` is literal and every name is UTC,
  so an hour never has two names around a daylight-saving change, and a name
  means the same hour on every node, whatever its time zone.
- **A directory per UTC day** (`YYYY/MM/DD`), so a day or a month can be copied,
  measured or removed with ordinary tools:
  `du -sh trace_archive/2026/09`, `rsync -a trace_archive/2026/09/26 backup:`.
- **Names sort in time order, and globs select periods:**
  `traces-2026-09-26T*` is a day, `traces-2026-09-*` a month,
  `traces-2026-09-26T1[4-7]Z*` is 14:00–17:59.
- A trace belongs to the hour its request **started** — the order the live store
  keeps them in. An hour with no traces has no file.

### Reading a file

A file is NDJSON — one trace per line, the JSON the trace API returns —
compressed with zstd:

```sh
zstd -dc traces-2026-09-26T14Z.ndjson.zst | jq 'select(.status | startswith("5")) | .path'
```

It also carries a header (the hour, how many traces, the first and last) and a
frame index, both in zstd *skippable frames* that `zstd` and every other decoder
pass over. `head -c 512 FILE` shows the header. The dashboard uses the index to
decompress only the part of an hour it needs; its checksum, and zstd's own on
each frame, make a damaged file fail to open rather than read short.

The archive holds exactly what the live store held: credential headers
(`Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, …) are already
`[REDACTED]` there, and bodies — captured only while the debugger is on for a
route — are archived as captured.

### When hours are archived, and when they go

- An hour is archived a couple of minutes after it ends; the archiver looks for
  work every minute.
- A trace is keyed by when its request started, so a long-lived connection can
  land in an hour that was archived long ago. The archiver checks each hour again
  shortly before the live store's retention reaches it, and merges any such
  traces in.
- The live store then deletes **whole hours, and only hours the archive has
  confirmed**. If archiving keeps failing — a full disk, a permissions problem —
  the store holds those hours back for up to 24 hours past its retention, then
  deletes them anyway rather than fill the disk. The dashboard shows the failure,
  and `gateon_trace_archive_unverified_prunes_total` counts those prunes.
- The archive has its own retention. An hour is deleted once it is older than
  the archive's retention, or, oldest first, while the archive is over its size
  limit — whichever binds first. Both are applied after every file written, so a
  first run over days of history stays within the size limit throughout. Files
  already written keep being aged out if archiving is turned off.
- Raising the archive's retention reaches back: hours the live store still has
  that the new retention covers are archived, while the archive is below 90 % of
  its size limit. An hour the limit pushed out is not written again.
- Where the store last pruned is kept in `gateon-pruned-through` among the
  store's own files, so a restart does not forget which hours only the archive
  still has.
- A trace's ID is the request's `X-Request-ID` as the client sent it. The store
  keeps at most 128 bytes of it, as valid UTF-8, because it is part of the key
  every cursor and archived line carries.

| Setting | Environment variable | minimal | standard | enterprise |
|---------|----------------------|---------|----------|------------|
| Archive on | `GATEON_TRACE_ARCHIVE_ENABLED` | off | off | off |
| Keep hours for | `GATEON_TRACE_ARCHIVE_RETENTION_DAYS` | 7 days | 90 days | 365 days |
| Size limit | `GATEON_TRACE_ARCHIVE_MAX_MB` | 256 MB | 2 GB | 20 GB |
| Directory | `GATEON_TRACE_ARCHIVE_DIR` | `<data dir>/trace_archive` | same | same |

An environment variable beats the global config (`log.trace_archive_*`), which
beats the profile. Settings changes apply within a minute, without a restart.

**One directory per node.** Each gateway archives its own traces. To gather
several nodes' archives in one place, give each its own directory — for example
`GATEON_TRACE_ARCHIVE_DIR=/mnt/archive/$HOSTNAME` — because two nodes writing one
directory would each replace the other's hours.

### Disk and CPU

Measured with `BenchmarkWriteSegment` (Apple M5 Pro, one core) on synthetic
traces shaped like real ones — random IDs and addresses, browser headers, no
captured bodies: about **920 bytes of JSON per trace, compressed about 7:1 to
roughly 130 bytes**, at about **390 MB/s of NDJSON** and about 6 MB of memory
while an hour is written. No JSON is parsed on the way out: the archive copies
the store's own records and compresses them.

So size the archive as `requests/day × ~130 B × days`. At a sustained
100 requests a second that is about 1.1 GB a day, and the standard profile's
2 GB limit, not its 90 days, is what binds. Captured bodies are larger and
compress differently; measure your own with `du`.

### Finding traces by period

**Traces → History** queries any period — a preset, or a custom range in your
local time. The part of the period the live store still holds is read from it,
the part before that from the archive, and the two come back as one list, newest
or oldest first, filtered by status class, method or text. A trace opens in full
whichever of the two holds it. **Traces → Archive** lists the archived hours with
their trace counts and sizes, opens any hour in History, and downloads it as
stored or decompressed.

One query call reads at most 200 000 traces, or 256 MiB of them, before
returning what it found with a cursor to go on from. One period query runs at a
time — another waits up to 30 seconds, then is told to try again — so a broad
search over a year takes at most one core from the proxy, briefly. A query reads
the live store through a snapshot, so a prune that lands while it runs cannot
make a page skip an hour.

At most four hours download at once (a fifth gets `503` with `Retry-After`),
each write has a 30-second deadline so a client that stops reading lets go, and
every download is sent `Cache-Control: private, no-store` and as an attachment
the browser may not sniff. A decompressed download that fails part-way is cut
off rather than ended cleanly, so a short file cannot pass for a whole one.

| API | Access |
|-----|--------|
| `QueryTraces`, `ListTraceArchives` RPCs | read on diagnostics |
| `GET /v1/traces/archives/{name}` (`?format=ndjson` to decompress) | read on diagnostics |

Metrics: `gateon_trace_archive_segments_written_total`,
`gateon_trace_archive_traces_written_total`, `gateon_trace_archive_bytes`,
`gateon_trace_archive_errors_total{stage="export|verify|retention"}` and
`gateon_trace_archive_unverified_prunes_total`.

## In-memory cache bounds

The telemetry subsystem keeps several in-memory LRU/ARC caches. Their capacities
are configurable via environment variables (entry counts). Invalid or
below-minimum values fall back to the default and log a warning.

| Env var | Cache | Default |
|---------|-------|---------|
| `GATEON_TELEMETRY_ZEROTRUST_CACHE_SIZE` | Zero-trust user→location | 100000 |
| `GATEON_TELEMETRY_REPUTATION_CACHE_SIZE` | IP reputation (sharded) | 100000 |
| `GATEON_TELEMETRY_BEHAVIOR_CACHE_SIZE` | Per-IP behavior (sharded) | 10000 |
| `GATEON_TELEMETRY_SCORE_CACHE_SIZE` | IP threat score | 10000 |
| `GATEON_TELEMETRY_UNMITIGATED_CACHE_SIZE` | Unmitigated threats | 1000 |

Sharded caches divide the configured total across shards (each shard floored at
1 entry).

## Observability

Two Prometheus gauges expose effective limits and live occupancy so you can size
caches against real traffic:

- `gateon_telemetry_cache_capacity{cache="..."}` — configured maximum entries.
- `gateon_telemetry_cache_entries{cache="..."}` — current entries (shards summed),
  refreshed every 15s.

## Runtime profiling (pprof)

Profiling is **disabled by default**. Set `GATEON_PPROF_ADDR` to bind the
`net/http/pprof` endpoints on a dedicated listener for live CPU/heap/goroutine
analysis:

```bash
GATEON_PPROF_ADDR=127.0.0.1:6060 ./gateon
go tool pprof http://127.0.0.1:6060/debug/pprof/heap
```

> Security: pprof leaks internal state and is a DoS vector. Bind it to loopback
> only and never expose it on a public interface. It runs on its own listener,
> separate from the proxy/API ports.

To catch allocation/performance regressions offline, run the benchmark suite with
profiling enabled:

```bash
make bench   # -benchmem + CPU/heap profiles written to dist/
```

CI also runs the benchmarks (`pkg/proxy`, `internal/telemetry`) with `-benchmem`
on every push/PR.
