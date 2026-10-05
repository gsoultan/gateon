# 62. What the gateway sends is what it decided: framing, paths, streams, passes and listeners

Date: 2026-10-04

## Status

Accepted. `net` drives (listeners, HTTP/3, health checks, balancing) with
`perf` for the request-path pieces; `sec` co-signs the path refusal, the
proof-of-work binding and the tls_binding change; `qa` for every fix (each
ships a test that failed before it); `obs` for the unverified-clients gauge.

## Context

The second production-readiness review (2026-10-04) left eleven data-plane
findings open. They share one shape: the gateway decided one thing and put
another on the wire, or decided once and never looked again.

- **T39.** A response the WAF refused (a DLP block) was sent under the origin's
  headers: the origin's `Content-Length` framed the 47-byte refusal of an
  83-byte leak, so clients read a truncated response (`IncompleteRead`) and an
  HTTP/1.1 connection waited for bytes that never came; a gzip origin's
  `Content-Encoding` made the refusal undecodable.
- **DP-F4.** `peekBody` put the peeked bytes back twice. Every POST with a body
  to a route with `enable_body_entropy` reached the proxy longer than its
  `Content-Length` (502), and the engine scored a body the client never sent.
- **DP-F8.** `/public/..;/admin` is `/admin` to Tomcat and Spring (path
  parameters are stripped before dot segments are resolved) and an ordinary
  segment to the router; `\` (and `%5C`) is a separator to IIS and ASP.NET and
  a character to the router. The request ran the catch-all route's chain while
  the backend served `/admin`.
- **DP-N4.** An HTTP/3 response cut by the write deadline ended with a clean
  end of stream. A streamed response has no `Content-Length`, so a 64 MiB
  download that stopped at 77 KB read as complete. quic-go FINs the stream when
  the handler returns; `httputil.ReverseProxy` aborts a failed copy only when
  the request context carries `http.ServerContextKey`, which quic-go does not
  set, so the proxy returned normally.
- **DP-N5.** A proof-of-work pass was a MAC over address and User-Agent under
  the route's key, and every route without a secret shares one generated key:
  a pass earned at difficulty 1 admitted at difficulty 6, on any route sharing
  the key, and survived the operator raising a route's difficulty.
- **DP-N6.** The unverified-clients gauge was decremented before the challenge
  answer was checked: 1000 forged answers took it to -1000.
- **DP-N7.** ADR 0042 lifts a response off the entrypoint's deadlines when the
  server answers `200 text/event-stream`. On an app that stores uploads under
  the type the uploader chose, a client reading nothing held any object for the
  stream lifetime (an hour at minimal).
- **DP-N8.** A route's targets were health-checked one after another, each with
  a 5 s timeout and two failures to eject: k blackholed targets took ~k*10 s
  to leave rotation, and past three a tick outran the 15 s interval.
- **TRUTH-NEW-12.** A weight-0 target beside weighted ones is a standby
  (ADR 0047) but never took a request, even with every weighted target down:
  the route answered 503 with a live backend in its pool.
- **TRUTH-NEW-5.** tls_binding checked the first `session` cookie only;
  `session=OWN; session_binding=OWN; session=STOLEN` passed, and a backend that
  reads the last value served the stolen session.
- **OPS-N5.** Entrypoints were bound once at startup. One whose port was held at
  that moment answered 503 on `/readyz` until the gateway was restarted.

## Decision

1. **A refused response carries its own framing.** The WAF's refusal drops
   every header that described the origin's body (`Content-Length`,
   `Content-Encoding`, `Content-Range`, `Content-Disposition`, `ETag`,
   `Last-Modified`, `Digest`, `Accept-Ranges`) and sets its own length and
   `text/plain`. A refusal after the headers have left still sends nothing
   further; that truncation is visible as one.
2. **A peeked body is put back once.**
3. **Ambiguous paths are refused, not normalised.** `router.AmbiguousPath`
   flags a dot segment with parameters (`..;`, `.;`) and any backslash; the
   base handler answers 400 before route selection and before any route
   middleware, the WAF included, and `SelectRoute` selects no route for them as
   a backstop. Normalising was rejected: resolving `..;` or rewriting `\` to
   `/` is wrong for every backend that takes them literally, and no legitimate
   client sends a dot segment with parameters. `/cars;color=red` is unchanged
   (JAX-RS matrix parameters).
4. **A cut response is aborted, never completed.** The listener's
   `StreamWriter` records a failed write to the client (not
   `ErrBodyNotAllowed` or `ErrHijacked`, which lose nothing owed), and the
   listener ends such a response with `http.ErrAbortHandler`, which quic-go
   turns into a stream reset (`H3_INTERNAL_ERROR`), HTTP/2 into `RST_STREAM`
   and HTTP/1 into a closed connection. The HTTP/3 server also sets
   `http.ServerContextKey` per connection so `ReverseProxy` aborts by itself.
5. **A proof-of-work pass is bound to the route and the difficulty.** Each
   `pow` middleware derives its challenge-ID key and pass key from the route key
   with the route id and difficulty, once at construction; the request path
   pays nothing.
6. **The unverified-clients gauge moves down only for a verified answer**, and
   never below zero (an atomic count with a CAS floor; the gauge is moved in
   step, never `Set`).
7. **An event stream declares no length.** A response is lifted only when it is
   `200 text/event-stream` *and* carries no `Content-Length`. Requiring the
   client's `Accept` was considered and rejected: ADR 0042 fixed real streams
   fetched without it, and the client asking for the lift is the party the
   deadline bounds, so it adds nothing against this attack. The residual -- an
   app that streams user-typed content with no length -- needs a per-route
   streaming switch, which is a schema change and is left for a later ADR.
8. **Health checks run concurrently**, at most eight targets of a route at a
   time (a constant: it caps connections per route per tick and is nothing an
   operator tunes). A tick lasts at most ceil(targets/8) timeouts.
9. **Standbys serve when no weighted target is alive.** Round robin (the only
   balancer that reads weights) deals turns evenly over live weight-0 targets
   then, and stops when a weighted target returns.
10. **tls_binding refuses a session cookie, or its binding, sent more than
    once**, across every `Cookie` header. Which duplicate a backend reads is the
    backend's choice, so there is no "one that counts" to check.
11. **A listener that could not bind is retried** -- every entrypoint listener
    (HTTP over TCP, HTTP/3 over UDP, TCP, UDP) binds through one helper: the
    first failure is logged at ERROR and reported to readiness, then the bind is
    retried from 1 s doubling to 30 s until it succeeds (readiness and
    `gateon_entrypoint_up` recover) or the gateway shuts down. HTTP/3 is
    advertised in `Alt-Svc` only while its listener serves.

## Consequences

- Clients see a WAF refusal as a complete 403 with a correct length.
- Routes with `enable_body_entropy` accept POST bodies again.
- A request whose path contains `..;`, `.;`, `\` or `%5C` gets 400 everywhere,
  management plane included. A backend that served such paths on purpose stops
  receiving them.
- A cut response is a reset on every protocol; clients retry instead of keeping
  a truncated body. `ReverseProxy` no longer logs "suppressing panic" to stderr
  for cut HTTP/3 copies.
- Proof-of-work passes issued before the upgrade stop verifying (they last ten
  minutes); clients solve one more challenge.
- A `200 text/event-stream` that declares a length keeps the entrypoint's write
  timeout.
- Dead targets leave rotation in two ticks however many there are.
- A canary held at 0% beside weighted targets takes traffic when every weighted
  target is down (it is a standby by the same rule).
- A browser that holds the tls_binding session cookie under two paths or
  domains is refused like a binding mismatch.
- An entrypoint whose port frees after startup starts serving within 30 s,
  without a restart.
- Request-path cost: see the benchstat in the change's report (StreamWriter,
  router, data-plane request, proxy, WAF).

## Amendment (2026-10-05): a response larger than the inspection limit

Review 3 (F1) found decision 1 did not hold past `response_body_limit`. At the
limit the held prefix was flushed with no decision (for plaintext the engine
analyses the body only in its body phase, which ran after the handler
returned), the rest streamed, and the late refusal sent nothing further: a
card in the first bytes of a 5 MB export reached the client whole under a
clean 200, and the Security Hub, `gateon_request_failures_total` and the log
recorded a block.

- **At the limit the held prefix is decided before any of it leaves.** The
  response-body phase runs on what is held (for plaintext, also the write that
  crossed the limit, which the engine was already given); a refusal is a
  complete 403 as in decision 1, and a redaction that can no longer be spliced
  is still refused. A body the engine never reads (a type no data-leak rule
  matches) has its body phase run at its headers, before they are committed.
- **Bytes past the limit are uninspected, and counted as such**, once per
  response, in `gateon_middleware_waf_uninspected_responses_total{reason=
  "ceiling_reached"}`; the engine is no longer fed them. Inspecting them as
  they stream was rejected: gwaf analyses a body only in `ProcessResponseBody`
  over the whole accumulated body, so re-running it per chunk re-scores every
  earlier byte (inflating anomaly scores) and costs O(n^2), and a finding there
  could not stop bytes already sent. A response the engine refused to read
  because it passed the engine's own body limit (`request_body_limit`), let
  through by a fail-open or audit-only WAF, is counted the same way. A
  fail-closed WAF still refuses a plaintext response whose crossing write takes
  the engine past that limit, as before.
- **A refusal after the headers is an abort, recorded as one.** No body
  decision is made that late any more; should one be, later writes fail, the
  handler ends with `http.ErrAbortHandler` (a reset, as decision 4), and the
  event is recorded with action `aborted` (not mitigating) and logged as a cut
  response, never as a block.

Responses within the limit take the same path as before: the change adds no
allocation, lock or I/O there (benchstat in the change's report).

## Related

ADR 0041 (management credentials), 0042 (deadlines and streams), 0045 (bot
challenges), 0046 (tls_binding), 0047 (weights, health thresholds), 0049
(readiness).
