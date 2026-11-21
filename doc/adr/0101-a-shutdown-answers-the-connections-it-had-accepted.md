# 101. A shutdown answers the connections it had accepted

Date: 2026-11-17

## Status

Accepted. Completes ADR 0092 for the connections it could not cover.

## Context

ADR 0092 keeps the listening sockets open across a restart, so a connection
made while no gateway is running waits and is served. Restarting the released
v1.3.8 binary under a client that opens a new connection for every request
still lost a request about one restart in eight. The client saw an empty
reply a millisecond or two after the signal.

The cause is in `net/http`. `Server.Shutdown` first marks the server as
shutting down, then closes the listeners, then waits for connections. A
connection's goroutine reads the request and then checks that mark, and if it
is set returns without answering. So a connection the server accepted just
before the shutdown, whose request arrives or is read just after, is closed
with nothing sent. It is not in the socket's queue any more, so the next
process never sees it; the old process had taken it and then dropped it.

`Shutdown` is right for what it was written for: stop reading new requests.
A gateway restarted under traffic needs the other reading: stop taking new
connections, and answer the ones already taken.

## Decision

**A shutdown closes the listener first and tells `net/http` last.**
`internal/server/drain` wraps an `http.Server`:

1. Close the listener. With the socket handed over (ADR 0092) connections
   made from now on wait for the next process.
2. Wait for the accept loop to return, so no connection is half taken.
3. Wait until every accepted connection has had its first request reach the
   handler. `net/http` makes its drop decision before it calls the handler,
   so a request that has reached it will be answered.
4. Call `Shutdown`, which now finds only requests in progress and idle
   connections, and close whatever is left when the deadline passes, as
   before.

**A connection that never sends a request is given one second**
(`drain.FirstRequestGrace`) and then closed. `net/http` gives it five and
holds the whole shutdown for them; a browser's speculative connection is
enough to trigger that. A request follows its connection within a round trip
or a handshake. It is a constant, not a setting: nobody has a reason to tune
how long a restart waits for a client that is saying nothing.

It applies to every `http.Server` the gateway runs: each HTTP entrypoint, the
management listener, and the server a TCP entrypoint hands its HTTP
connections to.

## Consequences

- A restart of this build under load loses no request
  (`TestARestartOfThisBuildLosesNoRequest`, 40 consecutive runs clean where
  v1.3.8 failed 2 in 15).
- A restart with a silent connection open exits about four seconds sooner
  than before.
- One small allocation and one `sync.Map` entry per connection, removed at its
  first request. A request costs one context lookup and an atomic load. The
  map never holds more than the connections waiting to send a first request,
  which the entrypoint's connection limit bounds.
- An idle keep-alive connection is still closed at shutdown, and a request the
  client sends on it at that instant is lost. That is the ordinary keep-alive
  race; clients retry it on a reused connection, and it is not new.
- Long-lived connections are unchanged: closed when the drain ends.
- This fixes the build's own shutdown. A restart out of v1.3.8 is v1.3.8's
  shutdown and keeps the fault until the gateway is on a build with this.

## Alternatives

- **Count connections at `StateActive`** with the `ConnState` hook alone.
  `net/http` sets that state and then checks the shutdown mark, so there is
  still a window between the two. Settling at the handler closes it.
- **`SetKeepAlivesEnabled(false)` and wait for every connection to close.**
  HTTP/2 connections and event streams stay open, so every restart would
  wait out its grace.
- **Leave it.** One request in a few hundred restarts' worth of traffic, but
  it is the only request an upgrade loses, and the feature's claim is none.
