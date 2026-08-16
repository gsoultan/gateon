<!--
Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
SPDX-License-Identifier: MIT
-->

# Benchmark baseline

`AGENTS.md` asks for benchstat evidence on hot-path changes and vetoes "feels
faster" with no numbers. There was nothing to compare against, so this is the
first recorded baseline.

## Running

```sh
make bench                      # writes dist/bench.txt
go run golang.org/x/perf/cmd/benchstat@latest dist/bench.txt
```

To evaluate a change, capture before and after and diff them:

```sh
git stash && make bench && cp dist/bench.txt /tmp/before.txt && git stash pop
make bench
go run golang.org/x/perf/cmd/benchstat@latest /tmp/before.txt dist/bench.txt
```

**Only compare runs from the same machine.** Absolute numbers below are from an
Apple M5 Pro (darwin/arm64, 15 procs) and exist to record shape and order of
magnitude, not as a threshold any other machine should meet. A regression is a
delta against a fresh local baseline, never against this file.

`make bench` samples with `-benchtime 1s -count 8`. The previous `-benchtime
100x` was too few iterations to settle — it reported `BufferPoolGetPut` at 62ns
against a real 4.6ns, and a benchmark that is an order of magnitude out is worse
than no benchmark, because it gets quoted.

## Baseline — 2026-08-14, darwin/arm64, Apple M5 Pro

### internal/middleware — the full infrastructure chain

Recovery → AccessLog → Metrics, the chain every proxied request passes through.

| Benchmark | sec/op | B/op | allocs/op |
| :-- | --: | --: | --: |
| `InfraChain_TraceAll` | 529.5n | 818 | 14 |
| `InfraChain_TraceOff` | 463.2n | 610 | 7 |

Trace recording is on by default (`GATEON_TRACE_SAMPLE_RATE=1`) and costs 7
allocations per request. It cost roughly 2.1× the chain's latency until
`GetReputation` stopped taking a shard write lock per request; see
`internal/telemetry/reputation.go`.

These numbers are **not** comparable with any recorded before 2026-08-14. The
benchmark used to build its request with `httptest.NewRequest` inside the timed
loop, which parses a raw HTTP/1.1 message and allocates a 4KB `bufio.Reader`
every iteration. A memory profile attributed 94% of allocated bytes to the
harness and ~3% to all Gateon code in the chain combined, so the old ~5.5KB/op
was very nearly a measurement of `net/http`. See the comment in
`internal/middleware/bench_test.go`.

### pkg/proxy

| Benchmark | sec/op | B/op | allocs/op |
| :-- | --: | --: | --: |
| `ServeHTTP` | 35.77µ | 7.837Ki | 103 |
| `ServeHTTP_Parallel` | 10.19µ | 12.92Ki | 111 |
| `RoundRobinLB_Next` | 1.848n | 0 | 0 |
| `LeastConnLB_Next` | 2.767n | 0 | 0 |
| `WeightedRoundRobinLB_Next` | 3.231n | 0 | 0 |
| `GetOrCreateProxy_CacheHit` | 1.646n | 0 | 0 |
| `BufferPoolGetPut` | 4.854n | 0 | 0 |

The load balancers, the proxy cache and the buffer pool are all allocation-free
and should stay that way — those five zeroes are the useful assertion here.
`ServeHTTP` includes a real backend round trip, so its microseconds are mostly
loopback, not gateway.

### internal/telemetry

| Benchmark | sec/op |
| :-- | --: |
| `ReputationHotPath` | 49.64n |
| `GenerateJA4H` | 31.48n |

## PGO

`cmd/gateon/default.pgo` is committed and `go build ./cmd/gateon` applies it
automatically — confirm with `go version -m <binary> | grep pgo`. Regenerate
with `make pgo-profile`.

PGO affects the built binary, so **none of the benchmarks above measure it**:
`go test -bench` compiles the package under test, not `cmd/gateon`. Measuring it
needs traffic through the real binary, which is what `TestPGOImpact` in
`tests/e2e/load_test.go` does:

```sh
GATEON_LOAD_TEST=1 go test ./tests/e2e/ -run TestPGOImpact -v -timeout 40m
```

It builds `./cmd/gateon` twice — once as shipped, once with `-pgo=off`, each
verified via `go version -m` so a null result cannot be two identical builds —
then drives 20k requests at concurrency 32 through each, over five rounds,
alternating which binary goes first.

### Result on the reference machine — 2026-08-15, Apple M5 Pro

**Not resolvable.** Median throughput differed by **-1.56%**, against an **18.5%
spread within a single binary's own five rounds**. The effect is far below the
measurement's own noise floor.

Read that as a statement about the harness, not about PGO. Loopback, mock backend,
load generator and gateway all share one laptop; round 5 ran ~15% faster than
round 1 for *both* binaries, which is drift on that scale, not code.

The alternating design is what makes this trustworthy, and it earned its keep
immediately: an earlier single-pair run — PGO first, no-PGO second, one sample
each — reported **+1.53% in PGO's favour**. Five alternating rounds put the
median at -1.56%. The sign flipped, which is what noise does and a real 1.5%
effect does not. A single pair would have shipped a fake win into this file.

To actually resolve a 1-2% effect you need the load generator on a separate host
from the gateway, a machine that is otherwise idle and thermally stable, and more
rounds. Until then the honest claim is "PGO is applied", not "PGO is worth N%".

For a profile that reflects real traffic rather than these benchmarks, set
`GATEON_PPROF_ADDR` and capture `/debug/pprof/profile?seconds=60` under load,
then install that as `default.pgo`.
