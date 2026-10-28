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

### The upstream half — gwaf v0.6.1, 2026-09-06

A profile after the body-read change put **90% of the remaining 2060 allocations
on one line of gwaf**: `internal/engine/eval.go`, `e.ctx.Key = string(v.Key)`,
run once per (reading x group x candidate rule) while the key is constant across
all of them. Its comment called that path "rare on real traffic"; on a benign
16 KiB JSON POST against a large ruleset it was 90% of every object allocated.

Fixed upstream in gwaf v0.6.1 — materialised at most once per value, lazily,
because hoisting it outright broke gwaf's own zero-allocation SLO for requests no
rule is a candidate for.

| Benchmark | allocs/op at v0.6.0 | at v0.6.1 |
| :-- | --: | --: |
| `WAFRequestWithInboundDLP` | 2060 | **563 (-72.67%)** |
| `WAFRequestWithoutInboundDLP` | 2060 | **563 (-72.67%)** |

Bytes fell from 57.9 KiB to 34.4 KiB on the same benchmarks. Taken with the
body-read change, the request path went from **142.9 KiB and 2081 allocations**
to **34.4 KiB and 563** — a quarter of the bytes and a quarter of the objects.

Worth recording for whoever profiles gwaf next: this is **not reproducible in
gwaf's own benchmark suite**. `RulesetScaling` keys its synthetic rules on tokens
no benign body contains, so the prefilter nominates nothing and it measures the
prefilter rather than the evaluator — which is why it reads 0 B/op at 10,000
rules. Five attempts at an in-tree reproduction are documented in that release's
commit message. The verification stands on the paired measurement above.

**What is left is not gateon's.** On the response path **82% of allocated bytes
are inside `gwaf/internal/memz.Arena`** — 1.8 MiB reserved for a 256 KiB body —
which was open upstream until gwaf v0.6.6 (below). Gateon's own share of these
paths has been paid.

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
  inspection needs to get cheaper. It was attacked, in gwaf v0.6.6 (below).

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

### The response arena — gwaf v0.6.6, 2026-10-28, linux/amd64, 4 vCPU Xeon (shared)

The 7× above was two things inside gwaf's transaction arena. `WriteResponseBody`
appended chunk by chunk and the arena doubled its way up, so the copies made at
each step summed to about twice the final capacity. Then `ProcessResponseBody`
copied the finished body into the arena a second time to record it as a value,
which needed room for two bodies and doubled the arena once more. gwaf v0.6.6
records the body where it already lies and sizes the arena once from a declared
`Content-Length`, which is a capacity hint only, bounded by the body limit,
and never decides what is inspected.

The same release closed two fail-open paths in that code: a response header
added between two body chunks left the end of the body uninspected, and a body
that fit the arena once but not twice was dropped without a value or a limit
decision. Neither is reachable from gateon's own call pattern today (it adds
every header before the first chunk, and its body limit sits well under the
arena's), which is why no gateon test changes with this bump.

The same `-count 6` run before and after the version bump, nothing else changed:

| Benchmark | sec/op | B/op | allocs/op |
| :-- | --: | --: | --: |
| `WAFResponseText` | −7.47% (p=0.009) | 1809.5Ki → **536.1Ki (−70.37%)** | 58 → 56 |
| `WAFResponseTextDeclaredLength` | −15.20% (p=0.004) | 1809.2Ki → **535.7Ki (−70.39%)** | 60 → 58 |
| `WAFResponseBinary` | +7.93% (p=0.041) | 259.9Ki ~ | 52 ~ |
| `WAFRequestWithInboundDLP` | ~ | 35.23Ki ~ | 561 ~ |
| `WAFRequestWithoutInboundDLP` | ~ | 35.26Ki → 35.18Ki | 561 ~ |

About half of the 536 KiB is gateon's own hold-back buffer, which holds the body
itself; gwaf's share is now about 1× the body. Plaintext streams into gwaf one
origin write at a time, and this benchmark's origin writes once, so both rows
get a sized arena and match. A proxied origin arrives in 32 KiB copy-buffer
pieces, and there the forwarded `Content-Length` is what keeps the arena from
doubling: gwaf's own 32 KiB-chunk benchmark is 272 KiB with it and 520 KiB
without, against 1.95 MiB before either. The `WAFResponseBinary` time is noise: that
path never reaches the code that changed, its bytes and allocations are equal to
the byte, and this machine moves ±10% between runs.

Reproduce with:

```sh
go test ./internal/middleware/security/waf/ -run '^$' -bench WAF -benchmem -count 6
```

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

## The proxy request path — 2026-10-26, linux/amd64, 4 vCPU Xeon (shared)

A pass over what one benign proxied request costs end to end on a 2-core /
2 GB budget: entrypoint chain, base handler, route chain, `pkg/proxy`. The
machine is a shared container, so `sec/op` here is ±10–40% between runs and
only the deterministic columns, `B/op` and `allocs/op`, are quoted as
evidence; latency is reported where benchstat found it significant.

`BenchmarkGatewayChain` in `internal/server` is new: the whole chain against a
stub backend with no socket, with the telemetry store open and trace recording
at the standard tier's sampling, so a delta is the gateway's and not the
loopback stack's. `BenchmarkDataPlaneRequest` spends ~140 µs of its ~200 µs in
the kernel and could not resolve a 10 µs change.

| Benchmark | before | after |
| :-- | --: | --: |
| `GatewayChain/no-tracing` (sec/op · B/op · allocs/op) | ~20 µs · ~10 KiB · 88 | **12.8 µs · 5.5 KiB · 47** |
| `GatewayChain/tracing` | ~20 µs · ~10 KiB · 90 | 16.4 µs · 8.9 KiB · 67 |
| `InfraChain_TraceAll` | 2.68 µs · 818 · 14 | 1.79 µs (−33%) · 770 · 12 |
| `InfraChain_TraceOff` | 610 · 7 | 578 · 6 |
| `HTTPEntrypointConnection` (B/op · allocs/op) | 10.58 KiB · 112 | 9.55 KiB · 100 |
| `pkg/proxy ServeHTTP` (allocs/op) | 103 | 99 |
| `pkg/proxy ServeHTTP_Parallel` (allocs/op) | 111 | 107 |

The "before" `GatewayChain` row is what cmd/gateon ran: `InitTracer` installed
an SDK tracer provider whether or not `OTEL_EXPORTER_OTLP_ENDPOINT` was set, so
every request recorded a span (3.6 µs, 2.4 KiB, 12 allocations, measured on its
own) that nothing exported. That was the single largest item in the profile
and the first change: with no endpoint there is no provider and the
`Telemetry` middleware starts no span, gated by `telemetry.TracingEnabled()`.
The `tracing` row is the cost once an endpoint is configured.

The rest of the gap, in profile order:

- **Trace recording** — `CloneHeader` ran twice per traced request and
  allocated a slice per header name; it now cuts the values from one backing
  array. On the store's goroutine, `RedactHeaders` spent a tenth of the
  gateway's CPU re-classifying `User-Agent` against the credential vocabulary
  on every request; `headerKindOf` remembers the answer per name, bounded at
  512 names of at most 64 bytes, forgetting all rather than evicting when full.
- **Request ids** — the span no longer replaces an id the entrypoint already
  made, the inbound `X-Request-Id` is read and set through one canonical
  constant so `net/http` does not re-canonicalize it per call, and the
  entrypoint's route label is built once.
- **Per-IP connection limit** — each address's in-flight count was a buffered
  channel built and dropped with the bucket on every lone request; it is an
  integer under the shard lock and the buckets are pooled.
- **Forwarding headers** — `pkg/proxy` set five headers with `Header.Set`, one
  slice each; they are cut from one array with capped sub-slices.
- **Smaller** — `PathTrie.Lookup` walks segments with `strings.Cut` instead of
  splitting; `RealIP` only rejoins host:port when the host changed; the base
  handler skips `MaxBytesReader` on a bodiless request; `MetricsWithService`
  resolves a fixed route's Prometheus series once instead of hashing the
  labels per request; `GetRecommendation` returns early while no
  recommendation has ever been registered; the honeypot path list is a
  package variable; JA4H and JA4+ are formatted in one allocation.

What remains at 47 allocations a request, for the next pass: the ARC caches
behind the mitigation and reputation checks take `any` keys, so each `Get`
boxes a string (≈6 allocations); the trace's two header clones (≈6); the
harness's own request and recorder (≈10). The typed `golang-lru/arc/v2` would
remove the boxing but is a new dependency and touches every store cache, so
it is left for its own change.

Reproduce with:

```sh
go test -tags=noebpf ./internal/server/ -run '^$' -bench GatewayChain -benchmem -count 8
go test -tags=noebpf ./internal/middleware/ -run '^$' -bench InfraChain -benchmem -count 8
```

## Caches and encoding — 2026-10-28, linux/amd64, 4 vCPU Xeon (shared)

The second pass over the proxied request path, taking up what the first left:
the caches behind the mitigation and reputation checks, and the trace and
access-log encoding. Same machine class and the same caveat: `sec/op` moves
±10–30% between runs, so the allocation and byte columns are the evidence.

| Benchmark | sec/op | B/op | allocs/op |
| :-- | --: | --: | --: |
| `GatewayChain/no-tracing` | 11.21µ → **10.08µ (−10%, p=0.004)** | 5.51Ki → **3.52Ki (−36%)** | 47 → **31** |
| `GatewayChain/tracing` | ~ (p=0.18) | 8.82Ki → **6.88Ki (−22%)** | 67 → **49** |
| `InfraChain_TraceAll` | ~ | 754 → **578** | 11 → **6** |
| `InfraChain_TraceOff` | ~ | 578 | 6 |
| `AccessLogLine` (new) | 3.74µ → **2.91µ (−22%)** | 842 → **728** | 15 → **7** |

`GatewayChain` counts every goroutine's allocations, the trace store's
included. Split by profile, per request:

| | before | after |
| :-- | --: | --: |
| request goroutine, gateway's own | ~24 objects · ~2.0 KiB | **~8 · ~1.0 KiB** |
| trace store goroutine | ~8 · ~2.5 KiB | **~7 · ~1.2 KiB** |
| harness (request, recorder, stub backend) | 16 · 1.6 KiB | 16 · 1.6 KiB |

What changed, in profile order:

- **Typed caches.** Every cache was `golang-lru`'s untyped ARC, so each
  `Get` on the enforcement path boxed its string key into an interface:
  eight allocations a request across the IP shun, the fingerprint block and
  release, and the two reputation reads. They are `golang-lru/arc/v2`
  generics now, with the same ARC policy and the same bounds. The one cache
  keyed by an address *or* a fingerprint (`unmitigatedCache`) takes a small
  comparable struct, so an IPv6 /64 is still a `netip.Addr` and nothing is
  formatted. The rest of the tree's LRUs moved to `golang-lru/v2` with them,
  and the type assertions on their reads went too. v1 stays in the binary
  through `go-immutable-radix`.
- **One header snapshot.** A trace cloned its request and response headers
  into two maps, about six allocations, to be walked once on the store's
  goroutine. Both sets are now one `[]string` of name/value pairs, formatted
  into the same text as before.
- **Off the request goroutine.** The trace's operation name and request URI
  were concatenated per traced request; the middleware hands over the method,
  path, host and a copy of the URL, and the store builds them before it
  redacts.
- **Nothing copied that did not change.** `RedactHeaders` returns its input
  when it masked nothing — nearly every response block; the day of a stats
  increment is formatted when the day changes rather than twice a request;
  a trace flush encodes into one buffer rather than one copy a record.
- **The access-log line** was eight `any` arguments, six of them strings
  boxed per line; it uses typed `slog` attributes. And with a `ReplaceAttr`
  installed, slog hands the level over as an `Any`, which the JSON handler
  encoded through `encoding/json` and reflection on every line; it is
  rewritten to its (constant) name first. The same `ReplaceAttr` called
  `Value.Time` without checking the kind, which panics on a caller's own
  attribute named `time`; it checks now.

What remains on the request goroutine: the request id (one string), the
request state in the context (two), JA4H+ and the reputation identity (one
each), the snapshot (one), and setting the id on the response header (two).

Reproduce with:

```sh
go test -tags=noebpf ./internal/server/ -run '^$' -bench GatewayChain -benchmem -count 6
go test -tags=noebpf ./internal/middleware/ -run '^$' -bench 'InfraChain|AccessLogLine' -benchmem -count 6
```

## Request id, JA4H+ and the trace snapshot — 2026-10-28, linux/amd64, 4 vCPU Xeon (shared)

The third pass, taking the eight objects the second left on the request
goroutine. benchstat, n=6; `sec/op` is noise at this size on a shared host.

| Benchmark | sec/op | B/op | allocs/op |
| :-- | --: | --: | --: |
| `GatewayChain/no-tracing` | ~ (p=0.59) | 3.54Ki → **3.34Ki (−6%)** | 31 → **27** |
| `GatewayChain/tracing` | ~ (p=0.70) | 6.85Ki → **6.67Ki (−3%)** | 49 → **45** |

- **The request id and its header value** are cut from a batch of eight
  (`request.NewIDHeader`), one `crypto/rand` read and one string and one
  slice per eight requests, taken from a `sync.Pool` so there is no lock. The
  entrypoint assigns the value to the canonical key instead of calling
  `Header.Set`, which built a one-element slice per request. Each value has
  capacity one, so an append under the same name reallocates rather than
  writing into another request's slot. What a retained id pins is bounded by
  the batch: 160 bytes for an id, 128 for a header value.
- **JA4H+** is a function of eight bytes and a two-bit mask. For the RFC 9110
  methods and PATCH, and no ALPN, h2, http/1.1 or h3, that is 2,304 strings,
  each built the first time a request produces it and returned after that from
  a fixed table of atomic pointers. A method or ALPN outside the table is built
  per request as before and never stored, so a client cannot grow or poison
  the table. `TestJA4HPlusTableIsExact` checks every slot against a longhand
  JA4H and that no two JA4Hs share a slot.
- **The trace's header snapshot** reuses a backing array kept on the pooled
  `TraceRecord`. `Reset` clears it so a pooled record holds no headers, and
  drops one grown past 256 entries.

What remains on the request goroutine: the request state in the context (two:
the `valueCtx` and the `Request` copy `WithContext` makes), the reputation
identity (one), and the response header map's first bucket (one), which
belongs to whichever header is written first, and the proxy writes headers on
every response anyway. The context pair cannot go without either pooling the
context, where a goroutine that outlives its handler would see another
request's cancellation, or reaching into `net/http`'s unexported fields. The
reputation identity scopes a client class to its network, so it has unbounded
cardinality and cannot be interned the way JA4H+ is.

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
