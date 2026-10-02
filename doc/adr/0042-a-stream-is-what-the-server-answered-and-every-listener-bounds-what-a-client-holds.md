# 42. A stream is what the server answered, and every listener bounds what one client can hold

Date: 2026-10-03

## Status

Accepted. Co-signed `net` ↔ `perf`/`mem` (and `sec`, for the header the client
wrote): it changes when a request's deadlines apply on every HTTP listener, the
memory a connection may hold before its request is read, and what the
management listener admits. Review findings A5 (dataplane F1), A6 (F2) and A11
(mgmt M7) of 2026-10-02, all reachable by an anonymous client on a default
install on the 2 core / 2 GB target.

## Context

**A client chose its own timeouts (A5).** Every HTTP entrypoint sets a read and
a write deadline per request (`dynamicTimeouts`, 15 s by default). It skipped
both for any request carrying an `Upgrade` header, whatever its value, or an
`Accept` naming `text/event-stream` -- on any route, whether or not anything
behind it streamed. Both are headers the client writes. An `Upgrade` request
then took the WebSocket path, which dialled a fresh backend connection, wrote
the client's body to it and read its answer with no deadline, and after a 101
copied bytes both ways with no idle timeout. A slow body or a slow read with
either header was held indefinitely (200 s observed, 15 s without the header);
over HTTP/2, `Accept` alone did the same per stream. HTTP/3 never had the
deadlines at all: the QUIC server was handed the entrypoint's handler without
them.

**A connection could buffer 1 MiB of header (A6).** `MaxHeaderBytes` was
1 MiB on every entrypoint and on the management listener, and HTTP/3 defaulted
to the same. A connection still sending its header is not a request, so no
in-flight limit sees it; only `ReadHeaderTimeout` (10 s) and the connection
caps bound it. 900 connections, each with an unterminated header just under
1 MiB, took the process from 102 MiB to 1292 MiB -- under the minimal tier's
1000-connection cap.

**One address made the management port answer 503 (A11 / M7).** The management
listener had `ReadHeaderTimeout` and nothing else, and no per-address cap. 510
connections from one address, each a `POST /v1/auth/2fa/verify` -- an
unauthenticated endpoint -- declaring a 100000-byte body and sending one byte,
filled the management chain's 500 in-flight slots, and every request on the
port, `/healthz` included, was answered 503 for as long as they were held. A
request turned away by that cap was not even answered: net/http drains a
request's unread body before writing the response, and that body never came.

## Decision

### A stream is recognised by its answer

Every request on every HTTP listener gets its deadlines, whatever headers it
carries. A response is lifted off them only once it *is* a stream, which the
server decides, not the client:

- **A WebSocket** when its backend has answered **101**. Until then the
  upgrade is an ordinary request: the client's side keeps its read and write
  deadlines -- a body sent with the upgrade is read under the read deadline --
  and the backend's answer is bounded by the HTTP transport's response-header
  timeout (1 min, `backendResponseHeaderTimeout`, now shared by both paths).
  The wait for the backend also ends when the client's request does, so the
  entrypoint's 15 s is what normally ends an upgrade nobody answers.
- **A server-sent-event stream** when the server has answered a **200 whose
  `Content-Type` is `text/event-stream`** (`deadline.StreamWriter`). The
  request's `Accept` decides nothing -- a real event stream fetched without one
  used to be cut at the write deadline, and now is not.

Once lifted, a stream is bounded by two values instead of none:

| | minimal | standard | enterprise | override |
| :--- | :--- | :--- | :--- | :--- |
| Idle: nothing moved, either direction | 2 min | 5 min | 10 min | `GATEON_STREAM_IDLE_TIMEOUT` |
| Maximum lifetime, however busy | 1 h | 4 h | 12 h | `GATEON_STREAM_MAX_LIFETIME` |

Both are `TierDefaults` (`StreamIdleTimeout`, `StreamMaxLifetime`); the
overrides take a Go duration, and `0` disables that bound. A byte in *either*
direction resets the idle timeout for the whole tunnel, so a backend pushing to
a client that never writes is not idle (`deadline.Clock`). Neither bound costs
a goroutine or a timer: a tunnel sets each read's and write's deadline from the
shared clock, and an event stream moves its connection's deadlines as it writes
-- at most once per sixteenth of the idle timeout, so the idle bound it gets is
between fifteen sixteenths of the configured value and all of it. On HTTP/1 the
read deadline is what ends a quiet event stream (the server's background read
times out and cancels the request); on HTTP/2 the write deadline does, by
resetting the stream.

This applies to the management listener's event streams too (the dashboard's
`/v1/watch` and the diagnostics streams). `EventSource` reconnects on its own
when one ends; `/v1/watch` sends a heartbeat every 15 s, inside every tier's
idle timeout.

### One header cap, sized from the tier

`MaxHeaderBytes` is `TierDefaults.MaxHeaderBytes` -- **32 KiB** minimal and
standard, **64 KiB** enterprise -- overridden by `GATEON_MAX_HEADER_BYTES`, and
set on every HTTP listener: the entrypoints over HTTP/1, HTTP/2 (net/http
derives `SETTINGS_MAX_HEADER_LIST_SIZE` from it) and HTTP/3, and the management
listener. A request past it is answered **431**. Over HTTP/2 a header list
modestly past the cap gets 431; one far past it, or a single field past it,
makes net/http close the connection instead (its CONTINUATION-flood and HPACK
guards), which refuses it all the same. 32 KiB is what nginx (4 × 8 KiB) and
Cloudflare allow; Envoy allows 60 KiB.

**The arithmetic.** The Go memory one connection holds while sending an
unterminated header just under the cap was measured (HeapInuse + StackInuse,
1000 connections, go1.27, darwin/arm64) at 28.1 KiB for a 16 KiB cap,
52.6 KiB for 32 KiB, 84.7 KiB for 64 KiB, and 1077.9 KiB for 1 MiB -- at most
1.7 × the cap + 4 KiB. A tier's connection cap filled that way:

| tier | connections | cap | worst case | sized against |
| :--- | :--- | :--- | :--- | :--- |
| minimal | 1000 | 32 KiB | 1000 × 52.6 KiB = **51 MiB** | a 512 MiB host: 10% |
| standard | 10000 | 32 KiB | 10000 × 52.6 KiB = **514 MiB** | the 2 GB target's 1536 MiB runtime limit (`GATEON_MEMORY_LIMIT`, production-runbook.md): 33%, leaving ~880 MiB beside a ~140 MiB baseline |
| enterprise | 50000 | 64 KiB | 50000 × 84.7 KiB = **4.0 GiB** | a 16 GiB host: 25% |

At 1 MiB the same rows were 1.0 GiB, 10.3 GiB and 51 GiB.
`TestHeaderBufferingFitsEachTiersMemory` fails if a tier's cap or connection
limit moves the worst case past half of what the tier is sized for. Against
the running gateway (minimal, macOS, RSS), the review's probe -- 900
connections each sending ~1 MiB of unterminated header -- went from
102 → 1292 MiB to 53 → 115 MiB peak, every connection answered 431 and closed;
900 connections each holding 31 KiB of header peaked at 127 MiB.

### The management listener bounds every request, and every address

- **Explicit timeouts**: `ReadHeaderTimeout` 10 s, `ReadTimeout` 30 s,
  `WriteTimeout` 5 min, `IdleTimeout` 1 min, on the server -- and applied per
  request by `deadline.RequestTimeouts`, which is what lets each kind of
  request get the bound that fits it:
  - **A body is bounded by progress, not by a total.** It has 30 s to start
    arriving and must then keep up **32 KiB/s**: each byte buys 1/32768 s. This
    port takes 2FA codes and 128 MiB GeoIP databases alike; the database
    finishes over a 256 kbit/s link, and a body sent one byte at a time is cut
    at 30 s.
  - **Once the request is in, the handler has 5 minutes**, from then: a WAF or
    GeoIP update and an AI analysis run inside their request.
  - **An event stream is lifted** to the stream bounds above.
- **A per-address connection cap**: ADR 0036's limiter and limit
  (`GATEON_ENTRYPOINT_MAX_CONN_PER_ADDR`, else `EntryPointMaxConnPerAddr`:
  128 / 256 / 1024), closing a connection past it at accept. Loopback and
  `GATEON_MITIGATION_ALLOWLIST` are exempt, and there is deliberately **no
  listener-wide cap**: it would refuse the operator on the host along with
  everyone else. One address can no longer reach the 500 in-flight slots, so
  `/healthz` keeps answering.
- **Unauthenticated bodies are capped at 64 KiB** (`publicBodyLimit` in
  `internal/server/base_handler.go`): login, setup, the setup database test and
  the two 2FA steps. Every other endpoint authenticates before it reads its
  body; these five were allowed the same 10 MiB, which at the per-address cap
  is gigabytes from one address.

### Where it lives

`internal/deadline` is the home of "how long a request may hold a gateway
connection": `StreamLimits` and their resolution, `StreamWriter` (the
event-stream lift), `Clock` (a tunnel's idle and lifetime) and
`RequestTimeouts` (the management listener's progress-bounded body). The
entrypoints, the management listener and `pkg/proxy`'s WebSocket tunnel import
it; it imports only `internal/config` and `internal/logger`.

## Consequences

- **A slow body or slow read is cut at the entrypoint's deadline whatever its
  headers**, over HTTP/1, HTTP/2 and now HTTP/3. A request that only carried an
  `Upgrade` or event-stream `Accept` header and relied on having no deadline --
  a long upload, a slow download -- now gets the entrypoint's
  `read_timeout_ms`/`write_timeout_ms` like any other; raise those on the
  entrypoint if it needs them.
- **A WebSocket idle for the idle timeout is closed**, and every WebSocket and
  event stream ends at its lifetime. Clients that do not ping, or that expect a
  socket to live for days, reconnect -- or the operator raises or disables the
  bound with the environment variables.
- **HTTP/3 requests now have the entrypoint's deadlines.** They had none.
- **A request header past 32 KiB (64 KiB on enterprise) is refused with 431.**
  A deployment whose clients send more -- very large cookies, long bearer
  tokens -- sets `GATEON_MAX_HEADER_BYTES`. It is a global setting, not per
  entrypoint, because the memory it bounds is the process's.
- **The per-request cost.** Every request on an HTTP entrypoint is served
  through a pooled `StreamWriter`: a sync.Pool get and put and one interface
  wrap. Benchstat, n=12 interleaved, darwin/arm64: `BenchmarkDynamicTimeouts`
  53.7 → 59.8 ns/op (+6 ns), 16 → 0 B/op and 1 → 0 allocs/op (the old header
  check allocated); `BenchmarkHTTPEntrypointConnection` (one request per TCP
  connection, the whole entrypoint) 99.7 → 100.8 µs, p=0.71, no difference,
  113 → 112 allocs/op. A stream pays a `time.Now` per write and a deadline move
  per sixteenth of its idle timeout.
- **Not changed.** The h2c and h3 *backend* transports still have no dial or
  response-header timeout of their own (review F9); the entrypoint's deadlines,
  which this ADR makes unconditional, are what bound them. gRPC server streams
  through the data plane are still cut at the write deadline, as before: they
  are not event streams, and nothing here lifts them. The management
  WebSocket at `/v1/logs` is upgraded by gorilla/websocket, which clears the
  connection's deadlines on hijack; it is bounded by its own handler, as before.
