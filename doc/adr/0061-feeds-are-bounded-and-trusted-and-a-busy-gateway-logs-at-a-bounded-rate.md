# 61. Feeds are bounded and trusted, and a busy gateway logs at a bounded rate

Date: 2026-10-04

## Status

Accepted. `mem` drives the feed index and the log budgets; `obs` co-signs the
metrics and the log-rate arithmetic; `sec` co-signs the feed URL and prefix
rules (a feed decides whom every entrypoint refuses, a trust boundary).

## Context

The 2026-10-04 production-readiness review found:

- **DP-N2.** Nothing bounded the IP reputation feed index (ADR 0044). It was a
  binary trie with a node per prefix bit plus a map from each host entry's
  text to its score. Measured here with a million random IPv4 entries: 498 MiB
  held, 989 MiB at the peak of every refresh, 698 MiB allocated per refresh.
  250k IPv6 entries held 859 MiB, so a million ran the 2 GB target out of
  memory.
- **TRUTH-NEW-4.** A feed line `0.0.0.0/0` or `::/0` refused every client of
  that family on every entrypoint, and a feed could be fetched over plain
  `http://`, so anyone on the path could decide whom the gateway refuses.
- **DP-N3.** One INFO line per WAF block and per audit-only would-block: one
  client sending attacks wrote 20,972 lines a second (measured, before),
  past journald's default budget (10,000 lines in 30 s), after which journald
  drops every line from the service, ERRORs included. The access-log cap of
  ADR 0049 bounded the one per-request line it knew about.
- **"Proxy error".** One ERROR line per failed proxied request: 10,375 a
  second against a backend refusing connections (measured, before).
- **OPS-N2.** The access-log cap was keyed on the request's start time and
  reset its count whenever that differed from the second it held, backwards
  as well as forwards: 644 lines a second through a cap of 100 (measured).
- **OPS-N8.** The entrypoint's metrics middleware recorded every request under
  the pseudo-route `gateon-<entrypoint>` and the route's recorded it again
  under the route, so every proxied request was twice in
  `gateon_requests_total`, the duration histogram, the byte counters, TTFB,
  and `gateon_requests_in_flight`.

## Decision

### The feed index is compact and bounded

Every feed entry carries the same score (100), so the index answers only
"is this address covered": sorted, merged address ranges per family (8 bytes
an IPv4 range, 32 an IPv6 one) and, from 1024 ranges, a 64 Ki-entry table on
the top 16 bits of the address so a lookup binary-searches one bucket.
Entries are read into fixed-size chunks and copied once into an exact-size
slice (a growing slice allocates ~5x its final size over its grows); one
feed's ranges are shared with its last good copy rather than copied.

The feeds are bounded per tier, across every feed, in entries **and** bytes:

| Tier | Entries | Bytes | Env |
| :--- | ---: | ---: | :--- |
| minimal | 250,000 | 8 MiB | `GATEON_IP_FEED_MAX_ENTRIES`, |
| standard | 1,000,000 | 32 MiB | `GATEON_IP_FEED_MAX_MB` |
| enterprise | 4,000,000 | 128 MiB | |

512 KiB of the byte bound is reserved for the two top tables. Feeds draw on
the budget in configured order; an entry past either bound is refused,
counted in `gateon_ip_feed_entries_refused_total{reason="over_limit"}` and
logged at ERROR once per feed per refresh. A feed that fails keeps its last
good copy only if that copy fits what is left. With one feed the index is
that feed's ranges; with more, each feed's copy is held beside the merged
index, so the memory held is at most twice the byte bound
(`gateon_ip_feed_bytes` reports what is held, `gateon_ip_feed_entries` the
entries in force). Measured (`BenchmarkFeedMemory`, 1M random entries):
IPv4 held 7.9 MiB, refresh allocation 39 MiB; IPv6 held 31 MiB.

### A feed cannot refuse everyone, and is read over TLS

A prefix wider than an IPv4 /8 or an IPv6 /32 is refused and counted
(`reason="too_wide"`). A /8 is a whole legacy class A and a /32 a registry's
usual allocation to one network; anything wider is not a reputation but an
outage. A feed URL must be `https://`; plain `http://` is accepted only to a
loopback address (127.0.0.0/8, ::1, `localhost`) -- a mirror on the gateway's
own host, with no network path to tamper on. There is no opt-in for private
networks: a LAN is a network, and a mirror there needs TLS like any other; no
new tunable. Enforced at save, on the path REST, Connect and gRPC share (only
URLs the save adds are judged, so a stored one does not hold unrelated saves
hostage), at every fetch (a stored `http://` feed is refused and logged each
refresh) and on every redirect.

### Per-request log lines have a budget

`logger.PerSecond` holds the window and its count in one atomic word, so
opening a window and counting in it are one compare-and-swap; the window only
moves forwards, measured on the monotonic clock from a start aligned to the
wall-clock second (so a window is the second a log timestamp shows). A line
stamped in an earlier window counts against the current one. The access-log
cap uses it and counts a line when it is written, not when its request began.

`logger.LineLimiter` is that budget plus per-key counts of what it left out:
the WAF block line, the would-block line (each keyed by rule and route) and
the "Proxy error" line (keyed by route and target, at ERROR) write their
first 10 lines a second, and report the rest one line per key at most every
30 s, at the level of the lines they stand for, saying since when. The report
is written by the next line after the interval, and by the server's existing
30 s task (`logger.ReportDue`), so a burst's tail is reported even if no such
line follows; `logger.FlushReports` writes what is left at shutdown. Keys are
bounded at 32 per limiter, overflow counted under `(other)`. The counters and
the Security Hub's records still see every event.

Arithmetic, standard tier: access log 100/s + 3 x 10/s + reports (at most
33 lines per limiter per 30 s) is about 133 lines a second worst case, under
journald's ~333. Measured after, under 31,000 attacks/s and 22,500 proxy
errors/s: 110-114 lines a second in total.

### Each request is counted once

The per-route families (`gateon_requests_total`,
`gateon_request_duration_seconds`, `gateon_request_bytes_total`,
`gateon_ttfb_seconds`, `gateon_requests_in_flight`) hold each request once:
under its route, or under `gateon-<entrypoint>` when no route took it. What
the entrypoint saw in all is its own family:
`gateon_entrypoint_requests_total{entrypoint,status_code}`,
`gateon_entrypoint_request_duration_seconds{entrypoint}` and
`gateon_entrypoint_requests_in_flight{entrypoint}`. The dashboard's headline
and funnel sum every per-route series; in flight is the entrypoint gauge,
which encloses the routes'.

## Consequences

- A feed listing more than the tier's bounds is partly not in force, loudly.
  A feed with a line wider than /8 or /32 loses that line. A stored `http://`
  feed off loopback stops loading.
- Under attack the journal holds ten WAF lines a second and a periodic count
  per rule; investigation goes to the Security Hub and the counters.
- PromQL that summed `gateon_requests_total` (or the histogram) over every
  route counted proxied requests twice and now counts them once; ratios (the
  runbook's 5xx alert) are unchanged, absolute rates halve, and the WAF
  rollout guide's would-block fraction, which was half its real value, is
  now right. Queries that read `route=~"gateon-.*"` as "all traffic" must move
  to `gateon_entrypoint_requests_total`.
- A named `metrics` middleware attached to a route is still a second view in
  the same families (deliberately, a set of routes measured together); it is
  the one remaining way to count a request twice there.
- Feed lookups for a listed address no longer hit an O(1) string map; a hit
  costs a parse and a bucket search. `BenchmarkFeedLookup`, interleaved runs,
  n=6: a miss -- the path nearly every request takes -- 32.0 -> 18.0 ns at a
  million entries and 25.9 -> 16.4 ns at 4096; a hit 6.4 -> 17.1 ns, paid
  only by a client about to be refused. No allocation either way.

## Alternatives considered

- **Keep the trie, cap entries.** Still ~500 bytes an IPv4 entry and ~3.4 KiB
  an IPv6 one; the bound would have had to be tiny. Rejected.
- **Allow `http://` to private networks behind an opt-in.** A new tunable for
  a weaker transport on a trust boundary. Rejected.
- **A timer per limiter for the report.** A goroutine per burst that outlives
  tests and races their log capture; the server's existing periodic task does
  the same job. Rejected.
- **An `entrypoint` label on `gateon_requests_total`.** Changes the identity of
  every existing series and still needs the entrypoint layer not to count
  routed requests. Rejected for a separate family.
