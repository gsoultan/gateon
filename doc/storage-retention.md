# Storage, Retention & Resource Bounds

Gateon keeps operational data in a few complementary stores. This guide documents
where the data lives, how it is bounded, how disk space is reclaimed, and the
environment variables you can tune to control memory and disk usage.

## Persistent stores

| Store | Backend | Holds | Location |
|-------|---------|-------|----------|
| Telemetry SQL | SQLite (default), Postgres, MySQL/MariaDB | Aggregated path/domain stats, security threats, audit rows | `gateon.db` (SQLite) or the configured DSN |
| Telemetry traces | Pebble (embedded LSM) | Per-request access-log / trace records | `telemetry_pebble/` next to the SQLite DB |
| Cache / rate-limit | Redis (optional) | Response cache, distributed rate-limit counters | External Redis |

> SQLite is used out of the box so a single binary is fully self-contained.
> Point the telemetry store at Postgres/MySQL for multi-node deployments; those
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
- For very high request rates, prefer a server-side SQL backend and a dedicated
  volume sized for `requests/day × avg-record-size × retention-days`, plus
  Pebble's transient compaction overhead (≈ one extra copy of the pruned range).

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
