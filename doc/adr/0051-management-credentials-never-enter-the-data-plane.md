# 51. Management credentials never enter the data plane

Date: 2026-10-04

## Status

Accepted. `sec` with `perf` (the withholding runs on every data-plane
request), `arch` because it moves the trust boundary ADR 0041 drew: from "the
backend" to "everything a route does".

## Context

ADR 0041 kept the dashboard's session from the backends: the proxy removes the
session cookie (`gateon_session`, `__Host-gateon_session`) and a session
bearer, and since ADR 0050 a `gateon_tok_` scrape token, before forwarding. It
did that in `ProxyHandler.ServeHTTP`, after the route's middlewares, on the
reasoning that they "still see the request as sent".

The 2026-10-04 review (MGMT-N1, high, operator to administrator) found what the
route's middlewares do with the request as sent:

- **forwardauth** copies every request header to its auth URL -- the `Cookie`
  line with the session in it, and any `Authorization`.
- **OAuth2 introspection** POSTs the request's token as `token=`, and
  `ExtractToken` read the session cookie *before* the app's bearer token: an
  administrator's browser had its session posted, not its app token.
- The same precedence made a route's own **JWT, PASETO and introspection**
  checks refuse the administrator's browser whatever app token it presented:
  they verified the session cookie, which is not theirs, and stopped.

A browser sends the dashboard's cookie to every app on the dashboard's host. An
operator -- who may create middlewares and bind them to routes, but may not
manage users -- could point a forwardauth or introspection middleware at a
server of their own, bind it to any route the administrator visits, and collect
an eight-hour administrator session.

## Decision

**Management credentials are withheld as a request enters the data plane.**
`CreateBaseHandler`'s outermost layer -- before telemetry, before route
matching, before any route middleware (forwardauth, introspection, the auth
middlewares, WAF, logging, everything) -- removes them from every request the
management plane will not answer:

- the session cookie under either name, from every `Cookie` line, keeping every
  other cookie byte for byte (a route's own `gateon_session_<route>` OIDC
  cookie included);
- each `Authorization` value -- every one, not the first -- that is a gateway
  API token (by its `gateon_tok_` shape) or a `Bearer v4.local.` token the
  management plane's verifier accepts. An app's own PASETO token does not
  verify under the gateway's key and passes.

"Will not answer" is the decision `mainHandler` and `HandleProxyOrLocal` already
make, taken before `SelectRoute`: a request is the management plane's when it
arrived on the management listener or an entrypoint sharing its address (those
never proxy), or when its path -- normalised as `SelectRoute` normalises it, so
`/v1/status/../../app` is the app's -- is the management API on an entrypoint
allowed to serve it publicly. Requests to the management plane are untouched.

Every data-plane protocol passes through this handler: HTTP/1.1 and h2 on HTTP
entrypoints, HTTP/3 (the same handler behind QUIC), plaintext HTTP and gRPC on
a TCP entrypoint (`buildPlainHTTPHandler`, ADR 0027), and WebSocket upgrades.
Raw TCP/UDP routes carry no headers and are out of scope, as in ADR 0041.

**The proxy keeps its strip, as the second line.** It is the one place every
protocol's request passes on its way to a backend, so a handler that ever
reaches the proxy another way is still covered. It now checks every
`Authorization` value; it read only the first, so a session sent as the second
value reached the backend.

**forwardauth and introspection refuse on their own, as the third line.** The
proxy cache hands the management plane's verifier to every route's middleware
factory (through the proxy handler, which already had it). forwardauth withholds
management credentials from the copy it sends the auth server. Introspection
reads its token with `ExtractAppToken`, which never reads the session cookie and
returns nothing for a management credential, so a session or scrape token is
never posted.

**Cost.** A request with nothing that could be a management credential -- nearly
all of them -- pays one scan of its `Cookie` and `Authorization` values: no
allocation, no global-configuration read, no verification. Tests pin zero
allocations and zero configuration reads for it. A cookie line naming the
session, or a `Bearer v4.local.`/`gateon_tok_` value, costs the plane decision
(one configuration read) and the strip. A `Bearer v4.local.` value is verified
once per request: the entry marks the request state, and the proxy then strips
by shape only, so an app whose clients send their own PASETO tokens pays the one
failed verification it paid under ADR 0041, not a second.

Measured, interleaved old/new test binaries, n=12 each (`BenchmarkDataPlaneRequest`
-- entrypoint middleware, base handler, route chain and proxy to a local backend
-- `BenchmarkServeHTTPCookies` and `BenchmarkInfraChain_*`): allocations and
bytes per request unchanged in every case (140, 136 and 153 allocs/op for no
credential, the admin's cookie, and an app's PASETO bearer; 92/93 in the proxy
alone; 14/7 for the infrastructure chain); time within noise everywhere
(p > 0.29 on a shared, loaded host).

## Consequences

- No route middleware and no backend sees the administrator's session cookie,
  a session bearer, or a scrape token, on any entrypoint or protocol.
- A route's JWT, PASETO and introspection checks authenticate an administrator's
  browser with the app's own token: the session cookie no longer reaches them.
- An app that used a cookie named exactly `gateon_session` or
  `__Host-gateon_session` for itself never receives it. Those names are the
  gateway's.
- An app whose clients send a `Bearer v4.local.` token pays one PASETO
  verification attempt against the gateway's key per request, as under ADR
  0041; a token that is not the gateway's fails at the MAC check. The proxy
  verifies again only for a request the entry did not mark -- one that reached
  it some other way.
- Not covered, as in ADR 0041: a client that sends its management token to an
  app under a header other than `Authorization` or in a query string.
- Middlewares that run before the plane is decided -- the entrypoint chain:
  request ID, metrics, mitigation, recovery, global honeypot and GeoIP, the
  entrypoint access log, connection and rate limits -- see management requests
  too, and none of them sends a header anywhere or records one unredacted (the
  access log records no headers; threats and traces redact `Cookie` and
  `Authorization`).
