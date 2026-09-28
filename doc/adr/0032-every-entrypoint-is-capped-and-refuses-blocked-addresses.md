# 32. Every entrypoint is capped, and every entrypoint refuses a blocked address

Date: 2026-09-28

## Status

Accepted. Co-signed `net` ↔ `sec`: it changes what every data-plane listener
admits, and where the IP block list is enforced. It supersedes the open point
in ADR 0029 that `IPMitigation` enforces an IP block on an allowlisted address.

## Context

Two admission decisions were made by some entrypoints and not others.

**The connection limit.** An entrypoint's `max_connections` was stored, shown
and read by nothing until #142 made TCP entrypoints honour it, with the
resource profile's default when it is 0. HTTP entrypoints still did not: an
HTTP entrypoint held as many connections as clients cared to open -- an idle
keep-alive connection for a minute, a silent one for ten seconds before its
first header -- each a goroutine, buffers and a descriptor, paid for by the
gateway alone. The per-IP limit (`GATEON_MAX_CONN_PER_IP`) counts requests in
flight, not connections, and reaches no idle connection at all.

**The IP block list.** An address shunned automatically or blocked by hand was
refused by every HTTP entrypoint (`IPMitigation`, per request) and, where eBPF
ran, dropped in the kernel. A TCP entrypoint without eBPF did not read the list:
a blocked address connected as freely as any other to an SSH, database or mail
backend, and on a tcp-only entrypoint -- which hands a connection to its backend
at accept -- straight to the backend, where an HTTP scanner never meets the
HTTP chain at all.

## Decision

### Every entrypoint holds at most `max_connections`

`max_connections`, or the profile's default when it is 0 -- **1000** `minimal`,
**10000** `standard`, **50000** `enterprise`
(`TierDefaults.EntryPointMaxConnections`, renamed from `TCPMaxConnections`) --
bounds every data-plane entrypoint: TCP as since #142, and now HTTP, plain and
TLS, HTTP/1, HTTP/2 and HTTP/3.

- **A connection is what counts, never a request.** The limit is taken on the
  listener, at accept (`cappedListener`), so an idle keep-alive connection
  holds its slot for as long as it is open -- it holds the descriptor, the
  goroutine and the buffers the limit exists to bound -- and an HTTP/2
  connection holds one slot however many streams it carries; those are bounded
  per connection by `h2MaxConcurrentStreams` (250). A limit counted in requests
  would have missed the idle connections and throttled multiplexing.
- **Before the TLS handshake.** On a TLS entrypoint the slot is taken when the
  TCP connection is accepted, so a connection past the limit costs its accept
  and a close, and no handshake.
- **The accept loop never waits.** A connection accepted while every slot is
  held is closed at once and the loop goes back to accepting, as the TCP
  entrypoint's does. `netutil.LimitListener` waits for a slot before it
  accepts, which leaves every connection past the limit queued in the kernel,
  unanswered, behind the ones holding it.
- **HTTP/3: a QUIC connection is a connection, from the same limit.** An HTTP/3
  entrypoint's QUIC connections take their slots from the limit its TCP
  connections do (`cappedQUICListener`): a client reaches it over one or the
  other, and the listener it picks is not a second allowance. One past the
  limit is closed with `H3_EXCESSIVE_LOAD` -- which a client sees as the
  transport's `APPLICATION_ERROR` when the close lands during the handshake
  (RFC 9000 10.2.3). Its handshake is done by then: quic-go completes it before
  a connection is accepted, so refusing a QUIC connection costs more than
  refusing a TCP one. That is the cost of QUIC living in user space, and it is
  still bounded. The refusal returns once the connection's own loop has sent
  the close -- the accept loop waits for that, never for a slot -- and while it
  does, quic-go's bounded accept queue holds the handshakes behind it.
- **Counted and said once a minute.** Every refusal is counted with the other
  connection-limit rejections (`inflight_rejected.max_connections` on the
  Diagnostics limit card; the fixed reason `http_max_connections`), and the
  entrypoint says it is full at WARN at most once a minute.
- A slot is released when its connection closes, once however often it is
  closed; a hijacked connection (a WebSocket) holds its slot until the handler
  closes it. The wrapper keeps `CloseWrite` and `ReadFrom` reachable, so
  net/http's half-close and sendfile, and the WebSocket proxy's half-close,
  work as they did.

**The management listener is not capped.** It is not an entrypoint in the
store, and takes no slot from any: each entrypoint counts only its own, so a
flood that holds a data-plane entrypoint full leaves management reachable
(`TestManagementStaysReachableWhileAnEntrypointIsFull`). A cap of its own
would be worse than none: anyone who can reach the port could hold its slots
and lock the operator out, which is the one outcome its separation exists to
prevent. What bounds it instead is where it listens -- loopback unless the
operator binds it wider, with its allowlist -- and the data-plane caps, which
leave the process's descriptors for it.

### Every TCP entrypoint refuses an address on the IP mitigation list

A TCP entrypoint -- the plaintext inspecting path, the tcp-only fast path and
the TLS-terminating path alike -- asks whether a connection's client is on the
list first thing in `tcpServer.handle`, before it reads a byte or makes a
handshake, and closes it if so. The refusal is recorded as the HTTP path
records one, as an `ip_mitigation` threat: counted on
`gateon_middleware_advanced_security_blocked_total` and listed in the Security
Hub, where the operator who blocked the address sees the block working. The
record goes through the telemetry store's bounded queue and is dropped, never
waited for, when the store is behind.

**On the connection's goroutine, never in the accept loop.** The list is read
from the database when its cache has no answer for the address; one slow
lookup in the accept loop would hold up every connection behind it
(`TestASlowBlockListLookupHoldsUpNoOtherConnection`).

**One rule, for both kinds of entrypoint: `identity.AddressBlocked`.** On the
list, and not exempt by `exemptFromEnforcement` -- loopback and
`GATEON_MITIGATION_ALLOWLIST`, the rule the fingerprint block and the
reputation blocker already applied. `IPMitigation` did not apply it: it
refused an allowlisted or loopback address on the list, which the allowlist --
documented as "never mitigated" -- says it must not, and which ADR 0029 left
open. Taking the HTTP path's check as it stood would have given the two kinds
of entrypoint different answers for the same address, so both now ask the one
function. The exemption is read only for an address the list would refuse.

## Consequences

- **Every HTTP entrypoint now has a connection limit it did not have** -- the
  profile's default unless `max_connections` says otherwise. An HTTP entrypoint
  that holds more concurrent connections than that (idle keep-alive ones
  included) now refuses the ones past it: on the standard profile, more than
  10000. It is read when the entrypoint starts.
- An HTTP/3 entrypoint's TCP and QUIC connections share one limit.
- The limit bounds what a flood of connections costs the gateway, not who
  pays for it: one client that opens `max_connections` slow connections holds
  the entrypoint full until they time out -- ten seconds without a complete
  header, a minute idle. Before, the same client cost the gateway without
  bound. A per-address connection limit is the complement and is not part of
  this decision; `GATEON_MAX_CONN_PER_IP` counts requests in flight, not
  connections.
- The dashboard shows the field on every entrypoint and says what 0 means; on
  a raw UDP entrypoint, which has no connections, it is disabled and says so.
- A TCP entrypoint looks each connection's client up on the list: one
  cache lookup per connection for an address it has seen, a database query for
  one it has not (cached after). Measured below.
- A connection from a blocked address to a TCP entrypoint is closed without a
  word; to an HTTP entrypoint it is still answered 403 per request.
- **A block reaches connections accepted after it.** An HTTP entrypoint asks
  per request, so a keep-alive connection is refused at its next request; an
  L4 session has no requests, and one already open when its address is blocked
  runs until it ends. eBPF, where it runs, drops the session's packets too.
  Ending open sessions on a block needs the block to reach the entrypoints as
  an event, which it does not today.
- A TCP entrypoint behind a proxy or load balancer sees the proxy's address:
  there is no PROXY-protocol input, so blocking the proxy's address refuses
  everyone behind it, as on an HTTP entrypoint without trusted proxies. Behind
  a local proxy every client is loopback, and exempt.
- An allowlisted or loopback address on the list is now served by HTTP
  entrypoints too. No automatic path puts one there (ADR 0029); what this
  changes is an operator's explicit block of an address they have also
  allowlisted, and blocks written before the upgrade.
- **Still not uniform: the kernel.** Where eBPF runs, `MarkIPMitigated` puts the
  address in the kernel's shun map without consulting the allowlist, so an
  allowlisted address on the list is dropped there. That is the eBPF sync's to
  change, not the entrypoints'.

### Measured

benchstat, n=10, the test binaries before and after this change run
interleaved, Apple M5 Pro, the telemetry store open in both as in cmd/gateon.
One connection per operation, 1000 operations a run -- more exhausts macOS's
loopback ports, which TIME_WAIT holds for 30 s:

| benchmark | before | after | |
| :--- | ---: | ---: | :--- |
| `TCPEntrypointHTTPSession` (client-first, HTTP through a TCP entrypoint) | 108.3 µs, 116 allocs | 118.2 µs, 118.5 allocs | time ~ (p=1.000), allocs +2.2% (p=0.000) |
| `ServerFirstSession/tcp-only` (server-first, tcp-only entrypoint) | 170.2 µs, 78 allocs | 175.1 µs, 80 allocs | time ~ (p=0.631), allocs +2 (p=0.000) |
| `HTTPEntrypointConnection` (one request per connection, HTTP entrypoint) | 86.3 µs, 109 allocs | 96.2 µs, 110 allocs | time ~ (p=0.393), allocs +1 (p=0.001) |
| `ServerFirstSession/direct` (control: no entrypoint) | 84.5 µs | 88.6 µs | ~ (p=0.579) |

No time difference is resolvable: the control, which nothing here changed,
varies by ±41-90% between runs. The allocations are, and are the ones the
design adds: two per connection a TCP entrypoint serves -- the client's
address as a string and the lookup's cache key -- and one per connection an
HTTP entrypoint admits, the wrapper that frees its slot. None per request.
The check alone (`BenchmarkTCPEntrypointBlockListCheck`, n=10) costs
**52-62 ns, 32 B and 2 allocations** per connection for a client the list's
cache has an answer for; a client it has not seen costs one database query,
on the connection's own goroutine, and is cached after.
