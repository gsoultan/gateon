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

## The WAF — 2026-09-04, darwin/arm64, Apple M5 Pro

These four benchmarks existed and ran green from the day they were written, and
**not one of their results ever reached this file**.

`go test` gives the test binary one stream for stdout and stderr and reprints it
all on its own stdout, so anything logged while a benchmark runs lands inside the
result row:

```
BenchmarkWAFRequestWithInboundDLP-15   2026/09/04 INFO gwaf: a rule cannot detect...
```

benchstat cannot parse that row, so it drops it — silently, with no warning and
no count of what it discarded. The noise was gwaf's rule diagnostics, emitted
once per engine build; gwaf logs to `slog.Default()` and gateon points that at
its own handler in production, so this was only ever a harness problem.
`internal/middleware/main_test.go` now discards the default logger while
`-test.bench` is set, and the rows arrive.

Worth stating plainly: the most security-critical hot path in the gateway had no
recorded baseline at all, and nothing anywhere said so. A benchmark whose output
never arrives is indistinguishable from one nobody wrote.

| Benchmark | sec/op | B/op | allocs/op | throughput |
| :-- | --: | --: | --: | --: |
| `WAFRequestWithInboundDLP` | 1.814m ± 2% | 142.9Ki | 2081 | 8.65 MiB/s |
| `WAFRequestWithoutInboundDLP` | 1.782m ± 5% | 142.9Ki | 2081 | 8.80 MiB/s |
| `WAFResponseBinary` | 24.90µ ± 6% | 260.5Ki | 54 | — |
| `WAFResponseText` | 3.674m ± 3% | 1.765Mi | 61 | — |

### The request path, improved — 2026-09-04

Once those rows existed, the first profile of them found where the money was, and
it was not the rules. `io.ReadAll` and `bytes.growSlice` accounted for **63.8% of
every byte allocated** on the request path, against **17.8%** for evaluating any
rule at all.

`readRequestBody` held the body twice — teed into a `bytes.Buffer` for replay to
the origin, and accumulated again by `io.ReadAll` for inspection — and both
copies grew by doubling from empty, so a 16 KiB body cost about six allocations
and copies per copy. Reading once, pre-sized from `Content-Length`, and replaying
from that same slice removes one whole copy and one whole growth chain. Sharing
is safe because nothing writes to it: gwaf's `SetRequestBody` reads and may
retain subslices, and the replay `MultiReader` only reads.

| Benchmark | sec/op | B/op | allocs/op |
| :-- | --: | --: | --: |
| `WAFRequestWithInboundDLP` | ~ (p=0.228) | **-59.45%** → 57.94Ki | -1.01% |
| `WAFRequestWithoutInboundDLP` | **-14.67%** → 1.521m | **-59.41%** → 57.99Ki | -1.01% |

Throughput on the non-DLP variant went from 8.80 to 10.31 MiB/s (+17.2%,
p=0.001). The declared length is treated as a hint and clamped to the configured
body limit, so a request claiming a gigabyte reserves no more than the WAF was
already willing to buffer.

**What is left is not gateon's.** A profile after the change puts **90% of the
remaining 2060 allocations inside gwaf's `engine.(*Evaluator).evalRule`**, and on
the response path **82% of allocated bytes inside `gwaf/internal/memz.Arena`**
(1.8 MiB reserved for a 256 KiB body). Both are upstream. Gateon's own share of
these paths has been paid.

Two things were tried and produced nothing measurable, recorded so they are not
tried again:

- **Pre-sizing the response hold-back buffer** from the origin's Content-Length.
  It changed no number. `bufReturnCeiling` (256 KiB) is deliberately far below
  the default `bufLimit` (1 MiB), so a buffer that holds a large response
  overshoots the ceiling and is discarded rather than pooled — an intentional
  memory-vs-CPU trade, not a defect. Reverted; speculative optimisation with no
  benchstat behind it is what `obs` vetoes.
- `BenchmarkWAFResponseTextDeclaredLength` was added while chasing that and is
  kept. The original response benchmarks never set `Content-Length`, so they only
  ever measured the chunked shape; the common one had no coverage.

What each one drives, because a number nobody can describe gets misquoted:

- **`WAFRequest*`** — a 16 KiB JSON POST of ordinary order data, no attack and no
  secret, at paranoia 2 against the full seeded ruleset. The benign shape is the
  deliberate choice: it is what ~all real traffic looks like, so it is the cost
  that actually gets paid. The two variants differ only in whether the inbound
  data-leak rules are loaded, and at 2081 allocations each they currently differ
  by nothing measurable — loading those 19 rules is not what this costs.
- **`WAFResponseBinary`** — a 256 KiB `image/png`. This is the content-type gate
  working: the body streams through unscanned, and the 260 KiB is the body
  itself, not a scan buffer.
- **`WAFResponseText`** — the same 256 KiB as `text/html`, fully inspected. The
  1.765 MiB is ~7× the body, which is the number to attack first if response
  inspection needs to get cheaper.

Two caveats on reading these:

- `httptest.NewRequest` is inside the timed loop for `WAFRequest*`, so roughly
  4.9 KiB and 7 allocations per iteration belong to the harness — about 3% of
  bytes here. That is tolerable, unlike the infrastructure-chain case above where
  the same mistake was 94% of allocated bytes and made the benchmark a
  measurement of `net/http`. It is written down so nobody re-derives it.
- Only the allocation columns are load-independent, and every one of them is
  ±0%. The `sec/op` figures came from a run whose nanosecond-scale rows elsewhere
  showed ±30–58%, so treat the milliseconds as order-of-magnitude and diff
  allocations when judging a change.

The `internal/middleware`, `pkg/proxy` and `internal/telemetry` numbers above are
from 2026-08-14/15 and were deliberately not re-recorded here — a baseline is
only useful as a fixed reference, and rewriting it because a later run was
noisier destroys the thing it exists for.

## The reputation blocker — 2026-09-04, darwin/arm64, Apple M5 Pro

`router.go` appends `ReputationBlocker` to every route's chain unconditionally,
so whatever it costs is paid by every proxied request on the gateway whether or
not the deployment has ever seen an attack. ADR 0010 changed the identity it
reads from a bare JA4+ fingerprint to that fingerprint scoped to the client's
network, which is more work on that always-on path.

| Benchmark | sec/op | B/op | allocs/op |
| :-- | --: | --: | --: |
| before ADR 0010 | 62.54n | 32 | 2 |
| naive scoped identity | 234.7n | 112 | 4 |
| **after optimisation, first consumer** | **117.5n** | **80** | **3** |
| **after optimisation, later consumers** | **89.9n** | **32** | **2** |

+275% was not acceptable for a check on every request, and the rule in
`AGENTS.md` is to make a check cheaper rather than weaker. Three changes got it
to +89%:

- **An allocation-free IPv4 fast path.** A `/24` is the text before the third
  dot, so it is a substring — no `netip.ParseAddr`, no `Prefix().String()`. The
  general path still handles IPv6 and anything malformed, and is allowed to be
  slow because it is rare.
- **Memoising the resolved client address** on the request state. The loopback
  guard and the identity build were each calling `request.GetClientIP`
  separately, so the forwarding headers were walked twice per request.
- **Resolving `EffectiveTrustCloudflare`'s environment fallback once.** It ran
  `TrimSpace`+`ToLower` on a `getenv` per call, and that fallback is taken on
  every deployment that has not written a WAF config — which includes every fresh
  install. An environment variable cannot change under a running process.

The residual allocation is the composite string itself, which has to exist to be
a map key. It is cached on the request state, so only the first of a request's
several reputation consumers pays it; the rest are back at the original 32 B and
2 allocations. The remaining latency gap on the warm path is hashing a longer key
into the reputation shard, which is inherent to a composite identity.

Reproduce with:

```sh
go test ./internal/middleware/ -run '^$' -bench 'ReputationBlocker' -benchmem -count 6
```

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

### Re-run — 2026-09-04, Apple M5 Pro

**Still not resolvable, and much more tightly bounded.** Median throughput +0.36%
(pgo 11,125 req/s vs no-pgo 11,084 req/s), against a **2.7%** spread within each
binary's own five rounds — so the effect remains below the noise floor, but the
noise floor itself came down from 18.5% to 2.7% on a quieter machine.

| | no-PGO | PGO |
| :-- | --: | --: |
| median throughput | 11,084 req/s | 11,125 req/s |
| within-binary spread | 2.7% | 2.7% |
| p50 | 2.516ms | 2.512ms |
| p99 | 11.494ms | 11.386ms |

The sign flipped again — -1.56% in August, +0.36% now — which is the third
consecutive result consistent with "no measurable effect on this hardware" and
inconsistent with any real effect of the size a single pair would have reported.

The conclusion is unchanged and now better supported: **PGO is applied; its
benefit is not measurable here.** That is the claim to make. A ten-fold reduction
in the noise floor without the effect emerging is itself evidence, and it is why
the number is recorded rather than the run being repeated until it says something
flattering.

For a profile that reflects real traffic rather than these benchmarks, set
`GATEON_PPROF_ADDR` and capture `/debug/pprof/profile?seconds=60` under load,
then install that as `default.pgo`.
