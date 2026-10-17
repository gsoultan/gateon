# 77. A management stream is re-authorized while it is open

Date: 2026-10-17

## Status

Accepted. Driver `sec`, challenger `conc`. It extends the guarantee of
[ADR 0012](0012-session-revocation-propagates-but-expiry-guarantees.md) (and
[ADR 0005](0005-session-lifecycle-and-first-run-trust.md)) from requests to
the streams the management plane holds open.

## Context

A session ends when its account is signed out, disabled, has its password
changed or is demoted: the token's session binding stops matching, and the next
request is refused (ADR 0005), on every instance within one binding TTL
(ADR 0012).

That guarantee was per request, and a management stream is one request that
does not end. Seven streams checked the caller once, when they opened:
`GET /v1/logs` (the system log over a WebSocket) and the server-sent event
streams `/v1/watch`, `/v1/audit/logs/watch`, `/v1/diag/security-threats/watch`,
`/v1/status/watch`, `/v1/diag/metrics/watch` and `/v1/diagnostics/watch`. They
then ran until the client left. The event streams were bounded by the stream
lifetime cap -- 1h, 4h or 12h by tier, the last longer than the 8h token
lifetime -- and the log WebSocket by nothing at all: gorilla clears the
connection's deadlines when it upgrades, the upgrader had no handshake timeout,
and the handler never read, so it saw neither pongs nor a vanished peer.

So an operator who disabled a compromised account, or demoted it, left every
stream it had open reading the system log, the audit trail and the live
security events, for hours.

The proto declares no server-streaming RPCs; these seven handlers are every
management stream.

## Decision

**Every management stream serves under a context that ends when the caller's
session no longer holds, and re-checks it on a clock.**

- `Deps.streamGuard` captures the token the request was authorized with and
  re-runs the request's own check every 30s (`streamRecheckEvery`, the binding
  TTL): `VerifyToken` -- the one verifier every request goes through, so the
  binding, the sign-out epoch and the expiry are checked exactly as they are for
  a request -- then `auth.Allowed` for the stream's permission, which also
  picks up an RBAC policy change. The first check that fails cancels the
  context, and the stream ends. There is no second implementation of the
  check.
- The stream also ends when the token expires, so no stream outlives the
  token that opened it, whatever the lifetime cap.
- A stream opened where the base handler waived authentication for the
  deployment has no session to lose and is not re-checked.
- The log WebSocket gets the bounds the listener cannot give a hijacked
  connection: a 10s handshake timeout, a reader that handles pongs with a 60s
  read deadline (pinged every 45s), a 10s deadline on each write, and the
  stream lifetime cap (`GATEON_STREAM_MAX_LIFETIME`). When its context ends it
  sends a close frame (1008) before closing.

Each stream costs one goroutine and one ticker for its lifetime, both ended
with the stream; a re-check is one `VerifyToken`, which the binding cache
serves without a database read at most once a TTL per account.

## Consequences

- A stream ends within one re-check interval of the revocation on the instance
  that made it, and within the binding TTL plus one interval on the others
  without Redis -- the same window a request has, plus at most 30s.
- The dashboard's streams end when its session does; reconnecting meets the
  ordinary 401, as any request would.
- A WebSocket client of `/v1/logs` that does not answer pings is disconnected
  after 60s. Browsers and the common client libraries answer them
  automatically. `doc/upgrading.md` says so.
- A stream opened before authentication was enabled for the deployment is not
  ended when it is enabled; it ends at its lifetime cap or when its client
  leaves.
