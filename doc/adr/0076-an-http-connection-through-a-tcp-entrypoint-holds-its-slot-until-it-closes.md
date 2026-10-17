# 76. An HTTP connection through a TCP entrypoint holds its slot until it closes

Date: 2026-10-17

## Status

Accepted. Driver `net`, challenger `conc`. It repairs the reach of ADR 0032
(`max_connections`) and ADR 0036 (the per-address cap and the block hook) on
one path, and moves no trust boundary.

## Context

A plaintext TCP entrypoint reads a connection's first bytes and, when they are
HTTP, hands the connection to a shared `http.Server` for that entrypoint
through a channel-backed listener (`sharedHTTPDispatcher`). The goroutine that
admitted the connection returned as soon as it had queued it, and its deferred
`openConns.remove` gave back everything the connection held: its
`max_connections` slot, its per-address slot, and its entry in the set
`closeByAddr` walks when an address is blocked. The shared server then served
the connection for as long as its client kept it alive.

So none of the three reached an HTTP connection on a TCP entrypoint. Reproduced:
an entrypoint with `max_connections: 2` served 20 of 20 concurrently held idle
keep-alive connections, and a blocked address's open keep-alive connection
stayed open until its idle timeout or its next request.

## Decision

**An admitted connection's slots are a lease, ended exactly once when the
connection is done with.** `serve` creates the lease (`connLease`) and the
goroutine serving the connection ends it on return -- unless the connection was
handed to the shared HTTP server. The hand-off wraps the connection
(`leasedConn`) so that its `Close` ends the lease, and marks the lease handed
off so the goroutine's own end does not release it early.

- The lease is a `sync.Once`, so the several closes net/http makes, a close by
  the block hook, and a close by shutdown release it once between them.
- `closeByAddr` and a forced shutdown close the socket beneath the wrapper,
  never the wrapper, so the lease is never ended under the `openConns` lock
  those two hold; the server's failed read closes the wrapper, which ends it.
- A connection queued for the shared server when its dispatcher closes is
  never accepted. `Close` drains the queue and closes each one, and a sender
  that finds the dispatcher closed after queuing drains it too, so no
  connection is left in the queue with a slot.
- The L4 paths are unchanged: they keep the bare socket, so splice(2) still
  reaches it, and their lease ends when their goroutine returns, as before.

## Consequences

- HTTP connections on a plaintext TCP entrypoint now count against its
  `max_connections` and the per-address cap for as long as they are open, idle
  keep-alive time included -- as they already do on an HTTP entrypoint (ADR
  0032). An entrypoint whose HTTP clients held more idle connections than its
  cap will refuse the excess. `doc/upgrading.md` says so.
- A block now closes an address's open HTTP connections on a TCP entrypoint,
  not only its L4 sessions.
- A TCP entrypoint's shutdown now waits for its handed-off HTTP connections,
  bounded by the shutdown deadline as its L4 sessions are; the shared HTTP
  server's own shutdown, which runs at the same time, closes the idle ones.
