# 36. A block reaches open L4 sessions, and every entrypoint caps connections per source address

Date: 2026-09-28

## Status

Accepted. Co-signed `net` ↔ `sec` (and `perf`): it changes when a block takes
effect on the data plane, and adds a second admission decision at every
entrypoint's accept path. It closes the two open points ADR 0032 named in its
Consequences: "A block reaches connections accepted after it" and "A
per-address connection limit is the complement and is not part of this
decision."

## Context

**A block reached only new connections.** ADR 0032 made every TCP entrypoint
refuse a blocked address at accept, so a connection *opened after* the block was
turned away. An L4 session already open was not: it has no request boundary at
which the block would otherwise reach it -- an HTTP entrypoint refuses a
keep-alive connection at its next request, but an SSH, database or mail session
sends no request the gateway sees, so it ran on until its client ended it.
Where eBPF ran it dropped the session's packets; the plaintext L4 path, and any
host without eBPF, did not. An operator who blocked an address mid-attack saw
new connections refused while the attacker's existing shell kept typing.

**One client could fill an entrypoint.** ADR 0032's `max_connections` bounds
what a flood of connections costs the gateway, but not who pays: one client that
opens `max_connections` slow connections holds the entrypoint full until they
time out. `GATEON_MAX_CONN_PER_IP` counts requests in flight, not connections,
and reaches no idle connection at all. There was no per-source-address bound on
concurrent connections at the entrypoint.

## Decision

### A block reaches the entrypoints' open sessions as an event

The mitigation write fires a block event. `telemetry.MarkIPMitigated` (an
operator's manual block) and `applyAutoShun` (an automatic shun -- a scanner, an
SSH brute-forcer) both call `fireIPBlocked(ip)` after they have seeded the cache
the request path reads, so a hook that re-reads the list sees the block. The
entrypoint layer registers one hook at startup (`RegisterIPBlockHook`), which
closes that address's open connections on every TCP entrypoint.

- **Driven by the event, never a scan on the hot path.** Each TCP entrypoint
  already tracks its open connections (`openConns`, ADR 0032, for drain). Those
  sets are registered in a process-global registry as an entrypoint starts
  serving and deregistered as it shuts down, so a hot-reload that replaces an
  entrypoint does not leak the old one. The hook iterates the registry -- the
  number of TCP entrypoints -- and each entrypoint's scan of its own
  connections is bounded by its connection cap. No per-request or per-connection
  work is added; the cost is paid once, on the block, by the goroutine that
  wrote it (an operator's API request, or the telemetry loop).
- **Bounded and non-blocking.** Closing a socket does not block. The scan holds
  one entrypoint's lock only long enough to close matching sockets; it does not
  wait for the serving goroutines to notice, so it cannot deadlock against a
  connection's own `remove`. The accept loop is never held up: the hook runs on
  a different goroutine, and touches the same lock only for the bounded scan.
- **The same exemption as the accept-time check.** The hook closes a
  connection only when `identity.AddressBlocked(ip)` is true -- on the list and
  not exempt from enforcement (loopback, `GATEON_MITIGATION_ALLOWLIST`) -- the
  one rule ADR 0032 settled on. An operator who blocks an address they have also
  allowlisted does not cut its open session, matching the accept path exactly:
  the allowlist is "never mitigated". An address released between the block and
  the hook is likewise left alone.
- **"Address" is the TCP peer, consistent with the accept-time check.** There is
  no PROXY-protocol input, so a TCP entrypoint behind a proxy sees the proxy's
  address (ADR 0032). The close reads each connection's peer the same way the
  accept-time check does, so what one refuses the other closes; behind a local
  proxy every client is loopback and exempt from both.

### Every entrypoint caps connections per source address

A per-address cap complements `max_connections`: **both** apply, and this is the
tighter for one client. On a TCP entrypoint (`openConns.add`) and on the HTTP
listener wrapper from ADR 0032 (`cappedListener`, and the QUIC listener), a
connection past a source address's cap is closed at accept.

- **The default is a per-tier `TierDefaults` value**
  (`EntryPointMaxConnPerAddr`): **128** `minimal`, **256** `standard`, **1024**
  `enterprise` -- generous enough for a browser's parallel connections and a
  shared NAT, tight enough that one address cannot use more than a small
  fraction of the entrypoint. `GATEON_ENTRYPOINT_MAX_CONN_PER_ADDR` overrides it;
  0 disables the cap.
- **Refused at accept, without blocking the loop.** A connection past the cap is
  closed at once and the loop goes back to accepting, as ADR 0032's
  entrypoint-wide refusal does. The per-address check is taken after the
  entrypoint-wide slot on the HTTP path and gives it back on refusal, so the two
  stay consistent.
- **Counted and said once a minute.** Every per-address refusal is counted with
  the other connection-limit rejections (`inflight_rejected.max_connections`;
  the reasons `tcp_max_conn_per_addr` and `http_max_conn_per_addr`), and the
  entrypoint says an address is at its cap at WARN at most once a minute.
- **Loopback and the allowlist are exempt.** `identity.ExemptFromEnforcement` --
  the same predicate the IP block uses -- so a local proxy, behind which every
  client is loopback, is never capped by the one address it shares, and an
  operator's allowlisted pentest team is not throttled.
- **The map is bounded by the connection cap, not the address space.** It holds
  an entry only while an address has a connection open, and the entry is deleted
  when its last connection closes. The number of distinct addresses tracked at
  once is at most the entrypoint's `max_connections`; a flood from many
  addresses is already bounded there.

## Consequences

- **A block now ends an address's open L4 sessions**, not only its new
  connections, on every TCP entrypoint -- with or without eBPF. On an HTTP
  entrypoint an open connection is still refused at its next request (ADR 0032);
  the event closes L4 sessions, which have no such boundary.
- An automatic shun ends the shunned address's open sessions too, so a scanner
  or SSH brute-forcer's existing connection is cut when it earns its shun, not
  only its next one.
- **Every entrypoint now bounds concurrent connections per source address** --
  the profile's default unless `GATEON_ENTRYPOINT_MAX_CONN_PER_ADDR` says
  otherwise. A single client that opened `max_connections` slow connections
  before now reaches its per-address cap first: on the standard profile, 256.
- The per-address cap costs **one allocation per connection a TCP entrypoint
  admits** -- the client's address as a string, read at accept -- and no
  resolvable time. Measured below.
- Behind a trusted proxy the per-address cap counts the proxy's connections, as
  the block does: there is no PROXY-protocol input. Behind a local proxy every
  client is loopback and exempt.

### Measured

benchstat, n=10, the entrypoint test binary run with the per-address cap off
(`GATEON_ENTRYPOINT_MAX_CONN_PER_ADDR=0`) and on (4096), interleaved,
one connection per operation, 300 operations a run:

| benchmark | cap off | cap on | |
| :--- | ---: | ---: | :--- |
| `TCPEntrypointHTTPSession` (client-first) | 135.8 µs, 116 allocs | 131.7 µs, 117 allocs | time ~ (p=0.912), allocs +1 (p=0.000) |
| `ServerFirstSession/tcp-only` (server-first) | 237.4 µs, 80 allocs | 233.7 µs, 81 allocs | time ~ (p=0.631), allocs +1 (p=0.000) |

No time difference is resolvable (the sessions vary ±11-27% between runs). The
one added allocation per connection is the client's address read at accept for
the per-address check; bytes per connection are unchanged within noise. None per
request. The block event adds nothing to any per-connection or per-request path:
its cost is a bounded, one-off scan on the goroutine that wrote the block.
