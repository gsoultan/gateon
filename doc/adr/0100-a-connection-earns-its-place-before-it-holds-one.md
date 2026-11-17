# 100. A connection earns its place before it holds one

Date: 2026-11-17

## Status

Accepted. `net` drives (entrypoint admission, HTTP/2 limits, the per-backend
cap); `sec` challenges every place a check could be stepped around; `mem`
challenges the new per-address state; `conc` challenges the locks on the
accept path; `perf` challenges the request path; `ops` signs off the new
defaults and their environment variables.

## Context

The 2026-11-13 security review ran gateon in a 2 CPU / 2 GiB cgroup on the
`standard` profile and took it out of service three ways, without one valid
request and without crashing it:

- **D1, silent connections.** Sixty addresses opening TCP connections and
  sending nothing held every one of an entrypoint's 10,000 slots. A
  connection that had proved nothing counted the same as one serving
  requests, held its slot for the full ten-second header timeout, and a full
  entrypoint refused the newcomer rather than the idlest holder. The
  legitimate client failed 183 of 189 requests.
- **D2, HTTP/2 rapid reset (CVE-2023-44487).** 128 connections opening and
  cancelling streams in a loop took the process to 76,848 goroutines and the
  cgroup's memory limit, and legitimate requests to a 5.3 s median. net/http
  bounds how many handlers a connection runs, not how fast its client opens
  and resets streams.
- **D3, no cap per backend.** Requests in flight to one backend were bounded
  only by the attacker's concurrency, 18,822 descriptors deep in D2.

Every change below had to be backward compatible with v1.3.8: nothing stored
and nothing on the wire changes, and a rollback has nothing to undo.

## Decision

**A connection is unproven until a request's headers have been read.** Not
the first byte: a slowloris that sends one byte has proved nothing. While
unproven (`internal/server/entrypoint/connguard`, `Unproven`):

- it has a deadline of its own, `EntryPointHandshakeTimeout` (5 s), or
  `EntryPointHandshakeTimeoutUnderPressure` (1 s) when it arrived with the
  entrypoint three-quarters full;
- one address (an IPv6 /64, as the per-address cap counts) may hold only
  `EntryPointMaxUnprovenPerAddr` of them (16, 64 on `enterprise`);
- when the entrypoint is full, the oldest unproven connection is closed to
  admit the new one, instead of the new one being refused.

Loopback and the mitigation allowlist are exempt from the per-address count,
as they are from the per-address cap, but still have the deadline and can
still be evicted. The tracker holds an entry only while its connection is
open and unproven, so it is bounded by the entrypoint's connection limit.

**An HTTP/2 connection that cancels streams faster than a browser does is
closed** (`connguard.Resets`, `H2MaxResetsPerSecond`, 100 a second, 200 on
`enterprise`), and the advertised `SETTINGS_MAX_CONCURRENT_STREAMS` drops
from 250 to 100 on `minimal` and `standard`.

**An address whose HTTP/2 connection was closed for rapid reset is refused at
accept for `H2ResetCoolOff` (10 s).** Closing alone bounded memory but not
CPU: the re-run showed the attackers simply reconnecting, the gateway still
parsing about two million frames a second, and the legitimate median at
2.7 s. net/http itself closed nine connections in ten, with
`ENHANCE_YOUR_CALM`, before the reset count had seen enough, and reports that
only through the server's error log, so the entrypoint watches that log for
the line and its peer address. The address in it is the TCP peer, not
anything the client wrote. A test drives the real server into that close and
fails if the format ever stops matching, so the signal cannot vanish
silently. The cool-off keeps at most 4,096 addresses; past that an address is
not cooled off but its connections are still closed. Addresses behind one
NAT share a cool-off, which is why it is short.

**Each backend target has an in-flight cap** (`BackendMaxInflight`, 256 /
1,024 / 8,192). A request that finds it full waits up to
`BackendQueueTimeout` (2 s) for a slot and is then answered 503 with
`Retry-After: 1`. The refusal is not charged to the target, so it does not
move the balancer or the health state. A WebSocket upgrade is not counted:
it holds its slot for the life of the connection, and the per-address and
entrypoint caps already bound those.

Every limit has an environment variable and a per-tier default
(`config.TierDefaults`); 0 turns off the per-address unproven cap, the reset
guard, the cool-off and the backend cap:
`GATEON_ENTRYPOINT_MAX_UNPROVEN_PER_ADDR`,
`GATEON_ENTRYPOINT_HANDSHAKE_TIMEOUT`,
`GATEON_ENTRYPOINT_HANDSHAKE_TIMEOUT_UNDER_PRESSURE`,
`GATEON_H2_MAX_RESETS_PER_SECOND`, `GATEON_H2_RESET_COOLOFF`,
`GATEON_H2_MAX_CONCURRENT_STREAMS` (a positive value overrides the profile),
`GATEON_BACKEND_MAX_INFLIGHT`, `GATEON_BACKEND_QUEUE_TIMEOUT`. Refusals are
counted with the other limit rejections under fixed labels:
`http_unproven_per_addr`, `h2_rapid_reset`, `h2_reset_cooloff`,
`backend_max_inflight`.

## Evidence

The review's harness (`2026-11-13-lab`), same cgroup, same profile, the
legitimate client opening a fresh TLS connection every 200 ms, before
(main at 776b310) and after:

| Attack | Before | After |
|---|---|---|
| Silent TCP connections, 60 addresses, 40 s | legit 185 of 188 failed; 10,056 goroutines | legit 0 of 133 failed, p50 49 ms; 1,016 goroutines, 89 MiB |
| Rapid reset, 128 connections, 60 s | legit p50 2.5 s, 1 timeout; cgroup at 2,048 MiB; 20,208 goroutines | legit p50 3.9 ms, p99 2.0 s, 0 failed; 175 MiB; 1,637 goroutines |
| Plain flood, 256 clients, 30 s | 10,145 req/s, legit p50 38 ms | 10,404 req/s, legit p50 37 ms, no 503 |

Without the cool-off, rapid reset gave memory 486 MiB but legitimate p50 2.7 s.
`BenchmarkServeHTTP*` in `pkg/proxy`, interleaved, shows no difference in time
and identical allocations.

## Consequences

- An idle keep-alive connection is unaffected: it has proved itself.
- A client behind a NAT shared with a rapid-reset attacker is refused for up
  to ten seconds. `GATEON_H2_RESET_COOLOFF=0` turns that off.
- A backend that legitimately serves more than its tier's in-flight cap at
  once answers some requests 503; raise `GATEON_BACKEND_MAX_INFLIGHT`.
- The remaining rapid-reset cost, a p99 of about two seconds while cool-offs
  expire and attackers reconnect, is CPU spent in net/http's frame loop. A
  longer cool-off or eBPF admission would cut it further; neither is a
  default.
