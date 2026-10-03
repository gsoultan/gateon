# 41. The dashboard session stays with the dashboard

Date: 2026-10-03

## Status

Accepted. `sec` with `ux` (the session cookie and what the dashboard may still
do), `perf` for the proxy half, `arch` because it moves a trust boundary: who
may act with an administrator's ambient credential.

## Context

The dashboard authenticates with one HttpOnly cookie, `gateon_session`, which
carries an eight-hour PASETO session token. The 2026-10-02 review found four
ways it reached, or acted for, someone other than the dashboard:

- **M4 (high).** A browser does not scope cookies by port. On the documented
  layout -- dashboard on `http://host:8080`, apps on `http://host/` -- every
  request to every app sends the cookie, and the proxy forwarded it. Live: a
  request to a route on 31082 carrying `other=1; gateon_session=…` reached the
  echo backend with both. Every backend behind the gateway received an
  administrator token it could replay from anywhere.
- **M5 (high).** Nothing checked who asked for a write. SameSite=Lax still
  sends the cookie on a same-site POST, and for a dashboard on an IP address or
  a shared domain "same site" is every port on that address and every sibling
  subdomain -- the proxied apps included. `POST /v1/global` with
  `Content-Type: text/plain`, `Origin: http://evil.example`,
  `Sec-Fetch-Site: same-site` and the cookie returned 200; one such request
  persisted `management.cors = {allowedOrigins: [evil], allowCredentials:
  true}`, which after a restart is permanent credentialed cross-origin access
  to the whole API.
- **M9 (medium).** The `/v1/logs` WebSocket upgrader accepted any Origin. A
  cross-site page may open a WebSocket and read it, so a same-site page with the
  cookie streamed the system log.
- **M15 (low).** Management CORS defaulted to `*`; API responses carried no
  `Cache-Control: no-store`; and `ExtractToken` accepted `?token=` whenever the
  request sent `Accept: text/event-stream`, a header anyone can send.

## Decision

**The proxy withholds management credentials.** `ProxyHandler.ServeHTTP` --
the one place every protocol's request passes on its way to a backend, HTTP/1,
h2, gRPC and the WebSocket upgrade alike -- removes the session cookie, under
either name, from every `Cookie` line before forwarding, keeping every other
cookie byte for byte. It runs after the route's middlewares, which still see the
request as sent. A `Bearer v4.local.` token is withheld when the management
plane's verifier accepts it (the proxy cache hands each handler the auth
`Holder`); a PASETO token the app minted under its own key does not verify and
passes. Raw TCP/UDP routes carry bytes, not headers, and are out of scope.

Cost, measured (benchstat, n=12, interleaved old/new binaries,
`BenchmarkServeHTTPCookies`): no session cookie, allocations unchanged at 92/op
and time within noise; with one, +1 allocation (+10 B/op), time within noise.
In isolation (`BenchmarkStripSessionCookie`): 0 allocations when absent, one
64-byte allocation and about 140 ns when present. A test pins zero allocations
for a request with neither credential.

**The cookie is `__Host-gateon_session` on a secure request.** A browser keeps a
`__Host-` cookie only if it is Secure, `Path=/` and has no `Domain`, so neither a
sibling subdomain nor a plaintext response on the same host can plant or
overwrite it. On plain HTTP the browser refuses the prefix, so the name stays
`gateon_session` there. The old name is still read on secure requests **for one
release** (the one after v2.7.0), so sessions signed in before the upgrade
survive it; signing in or out over TLS expires the old-name cookie. Remove the
old-name read in the release after: until then a cookie planted under the old
name is read when no `__Host-` cookie is present.

**SameSite is Strict.** The difference from Lax is only cross-site top-level
navigations: Lax sends the cookie when another site links or redirects a
browser into the dashboard; Strict does not. The dashboard is a single-page app.
Its HTML shell needs no cookie, and every API call it makes is a same-origin
fetch, which carries a Strict cookie. So Strict costs a signed-in user nothing:
following a link into the dashboard from email or chat loads the shell, and its
first API call is authenticated. What Lax would add is the cookie on GET
requests other sites start, which no part of the dashboard needs. Neither value
stops a same-site sender; that is the next point.

**One guard refuses writes the dashboard did not ask for.** `mgmtorigin.Policy`
wraps everything the management plane serves (outside its CORS handler, so a
refusal carries no CORS headers), sign-in and setup included -- a forged
sign-in into the attacker's account is a write too. For POST, PUT, PATCH,
DELETE and any WebSocket handshake it applies net/http's
`CrossOriginProtection` algorithm:

- `Sec-Fetch-Site: same-origin` or `none` is allowed; `same-site` and
  `cross-site` are refused unless `Origin` is a configured management CORS
  origin. No page can set or remove this header.
- Without it (a browser from before 2023), an `Origin` whose host is the
  request's own `Host` is allowed; any other, `null` included, is refused unless
  configured.
- With neither header the client is not a browser -- a script, Prometheus, the
  CLI -- and holds a bearer token rather than an ambient cookie. It is allowed.

The standard library's type is not used directly because it exempts GET, and a
WebSocket handshake is a GET. Comparing the `Origin` host with `Host` rather
than a scheme-qualified origin keeps a dashboard behind a TLS-terminating proxy
working without trusting `X-Forwarded-Proto`.

Behind it, an API write (`/v1/*`, `/gateon.v1.*`) must carry a body type a page
cannot send cross-origin without a preflight: `application/json`,
`application/proto`, `application/connect+*` or `application/grpc*`.
`multipart/form-data` is accepted only on the two file uploads
(`/v1/certs/upload`, `/v1/geoip/upload`); a write with no body needs no type.
That is the second line, for a browser that sends neither header. The
dashboard's `apiFetch` now labels a string body `application/json` itself,
because `fetch` calls it `text/plain`.

**`/v1/logs` checks the same way.** Its upgrader's `CheckOrigin` is the same
`Policy.Allows`, built from the same configuration, so it holds even if the
handler is mounted somewhere the guard does not reach.

**Management CORS is off unless configured.** With no
`management.cors.allowedOrigins` and no `GATEON_CORS_ORIGINS`, no CORS handler
is installed and no `Access-Control-Allow-Origin` is sent. The dashboard is
served from the management origin and never needed it. The configured origins
are also the only origins the write guard and the WebSocket check trust; `*`
is never trusted for writes.

**Every `/v1/*` and Connect answer a cache could keep carries `Cache-Control:
no-store`** -- the answers to GET, HEAD and POST, the only methods RFC 9111
lets a cache store; Connect calls are POSTs. It is set before the handler runs
so error answers carry it too. PUT, PATCH and DELETE answers are not cacheable
and get no header: marked no-store, a PUT answer's body is not kept by
Chromium's inspector, and the Playwright specs that read the dashboard's
`PUT /v1/global` answer waited on it until they timed out.

**A query-string token is accepted only on a WebSocket handshake** -- a GET with
`Upgrade: websocket`, `Connection: Upgrade` and `Sec-WebSocket-Key`, which is
what a browser's WebSocket API sends and the one place it cannot send a header.
No endpoint of gateon's own needs it for server-sent events: `/v1/watch` is
opened with `withCredentials` and authenticates with the cookie. The rule lives
in `ExtractToken`, which route-level JWT, PASETO and OAuth2-introspection
middlewares share, so an app's EventSource client that put its token in
`?access_token=` must now send it in `Authorization` or a cookie.

## Consequences

- No backend receives the dashboard session, whatever host or port layout the
  operator chose. The review's interim advice -- serve the dashboard on a
  hostname no proxied app shares -- is still good practice but no longer what
  keeps the session private.
- A same-site page can no longer write through the dashboard's cookie, nor read
  the system log with it. A legitimate cross-origin dashboard must be named in
  `management.cors.allowedOrigins` (or `GATEON_CORS_ORIGINS`); that is now what
  lets it write, not only read.
- Scripts are unaffected as long as they send neither `Origin` nor
  `Sec-Fetch-Site` -- curl, Python requests, Go's client and Prometheus send
  neither -- and send JSON. A script that sends a body as `text/plain`, a form,
  or no `Content-Type` at all gets 415; a script driven through a browser-like
  client that adds `Origin` gets 403 unless that origin is configured.
- Existing sessions on TLS survive the upgrade under the old cookie name, for
  one release. Operators whose tooling reads the cookie by name (it should not;
  it is HttpOnly) will see `__Host-gateon_session` over TLS.
- An app using query-string tokens for server-sent events through a route's
  auth middleware has to move the token to a header or cookie.
- Not covered: raw L4 routes (no headers to strip), and a client that sends its
  management token to an app under a header other than `Authorization`.
