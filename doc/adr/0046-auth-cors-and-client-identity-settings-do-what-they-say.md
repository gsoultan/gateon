# 46. Auth, CORS and client-identity settings do what they say, or are refused

Date: 2026-10-03

## Status

Accepted. `sec` drives, `ux` challenges: every decision changes what a route
accepts -- which tokens, which origins, which sessions, whose address -- and
what the dashboard tells an operator it does. ADR 0043's rule applies: a setting
that saves does what its label says, or the save is refused.

## Context

The 2026-10-02 truth review (T6, T14, T19-T22, T32, T35, T37) found eight
settings that saved and then did something else:

- **T6** "Enable Revocation" was offered for JWT, PASETO and OIDC. Only the JWT
  branch read it, and only with Redis configured. A revoked PASETO or OIDC token
  kept working; a JWT route with the switch on and no Redis -- the default --
  checked nothing.
- **T14** "Trust Cloudflare Headers" on rate-limit, IP-filter and GeoIP
  middlewares was ignored: the entrypoint resolves the client address once,
  under the global setting, and every middleware reads that answer.
- **T19** Required scopes typed as the placeholder showed them ("read, write")
  refused every valid token: the list was split on "," and " write" kept its
  space.
- **T20** `tls_binding` refused every TLS request carrying a session cookie and
  did nothing over plain HTTP. Its binding was keyed by the connection's TLS
  exporter, which no session survives, and nothing ever issued one.
- **T21/T35** XFCC's "Forward By" was read and never used, and certificate
  fields were written unescaped, so a URI SAN reading `spiffe://a;Hash=x` added
  a Hash pair of its holder's choosing.
- **T22/T37** The Permissive, Standard and gRPC-Web CORS presets paired origin
  `*` with credentials, which browsers refuse; an empty Allowed Origins let
  every origin in, while the same empty field under "Restricted" let none.
- **T32** Rate-limit "Storage: Redis" fell back to each instance's memory
  without a word.

## Decision

### Where a refusal lives

Two homes, by whether a stored config may keep building:

- **`Create`** (the factory, used by save *and* by every route build) refuses
  what must never run: revocation without Redis, `tls_binding` without a secret.
  A stored config then fails to build, and the router serves the 503 of an
  unbuildable security middleware -- fail closed, as ADR 0043 A9.
- **`Factory.Validate` → `checkSave`** (save only; REST, gRPC and config import
  share it through the domain service) refuses what a stored config may keep
  doing in a degraded, logged form: Forward By with no URI, credentials with
  `*`, Redis storage without Redis, a per-middleware Cloudflare trust that
  disagrees with the global one. Taking a route out of service on upgrade for
  any of these would cost availability and buy nothing.

### T6 -- revocation reads Redis, for every type that offers it

JWT, PASETO and OIDC refuse a verified token while the Redis key
`<revocation_prefix><jti>` exists (default prefix `revoked_jti:`), with the JWT
path's handling of a failed lookup -- refused, cause logged -- now shared. With
the switch on and no Redis the build is refused. **No in-process store:** the
gateway has no API to revoke a token; the operator's only writer is Redis. An
in-process list would have no writer at all -- the same inert switch -- and on a
cluster each node's list would differ. A token with no `jti` cannot be named by
the list and is not refused by it; the form says so.

### T14 -- the per-middleware Cloudflare switch is retired, not made real

Making it real would give one request two answers to "who is the client" --
the rate limiter believing `CF-Connecting-IP` while the WAF, reputation and logs
do not -- and let anyone who may edit a middleware move the trust boundary that
ADR 0040 gives an administrator. Invariant 8 (the resolver alone decides trust)
stays as it is. The narrow fix: a saved `trust_cloudflare_headers` that
disagrees with the effective global trust is refused, naming the setting that
decides; one that agrees still saves, so a re-imported export is not refused.
The dashboard drops the switch and the stored key. The rate limiter keys on
`request.ClientAddr`.

### T19 -- the parser reads what the form shows

Scopes split on commas and whitespace (RFC 6749: a scope never contains a
space); roles on commas, trimmed, since a directory group name may contain one.
Empty entries are dropped, so a trailing comma no longer requires the empty
scope.

### T20 -- a session is bound to the client certificate

RFC 8705's certificate-bound token, applied to the cookie a backend issues:

- When the backend's response sets the session cookie (`cookie_name`, default
  `session`) on a connection that presented a client certificate, the gateway
  adds `<cookie>_binding = HMAC(secret, label, cookie name, SHA-256(cert), value)`
  with the session cookie's path, domain and lifetime. An emptied or expired
  session expires its binding.
- A request carrying the session must come over TLS with a client certificate
  and present the binding that certificate and session produce. No
  certificate, another certificate, or plain HTTP: 403. A request with no
  session is not checked.
- The secret is required (32+ bytes), write-only, and shared by every node;
  changing it ends every bound session.
- A route save that puts `tls_binding` on an HTTP entrypoint without TLS (or on
  no named entrypoint, which means all of them, while one lacks TLS) is
  refused. Whether the entrypoint *asks* for client certificates is not checked
  at save -- a per-route TLS option can decide it -- and a request without one
  is refused with the reason.
- The connection-bound design is gone: a browser opens new connections when it
  likes, so no session could survive it. A certificate is what a client proves
  it holds in every handshake, and what a stolen cookie cannot bring along.

The global "TLS Session Binding" switch applied the old check to every route
with no secret to bind with; nothing it did protected a session. It is retired:
turning it on is refused (`InvalidArgument`), one already on installs nothing
and logs once, and the dashboard offers only turning it off. Binding is
per-route, where the secret lives.

### T21/T35 -- XFCC values are escaped; By names the gateway

A value holding `, ; = " \`, a space or a control character is double-quoted,
with `"` and `\` backslash-escaped (Envoy escapes the quote; escaping the
backslash too keeps a value ending in one from swallowing the closing quote); a
control character is written `%XX`. The subject is always quoted. Forward By
emits `By=<by>` first, where `by` is the URI the operator states -- in Envoy's
terms the URI SAN of the gateway's own certificate, which a middleware cannot
read (crypto/tls reports only the peer's, and an entrypoint may serve many).
Forward By without an absolute URI is refused at save; a stored one omits the
pair and logs.

### T22/T37 -- CORS: empty is none, and `*` never carries credentials

The three presets that grant `*` leave credentials off. A policy with `*` is
served without `Access-Control-Allow-Credentials` -- all a browser would honour
anyway -- and a save asking for the pair is refused, on cors and grpcweb. An
empty origin list on a cors middleware grants no origin; `*` grants every one.
A blank origin field beside a preset takes the preset's list (the form writes
the field either way). The grpcweb "Restricted" preset, whose empty list fell
into grpcweb's any-origin default, now grants none; grpcweb with no preset and
no origins keeps its documented default (any origin, never credentials).
Diagnostics still sees the configured credentials, so its warning about `*`
with credentials keeps firing.

### T32 -- Redis storage needs Redis

Refused at save without Redis. A stored config, or a gateway that has since
lost its Redis, limits per instance and logs `effective_storage=local` -- on one
node exactly the limit asked for. The form says Redis storage needs Redis.

## Consequences

- Fail-closed on upgrade (the upgrade note says so): a JWT/PASETO/OIDC route
  with Enable Revocation on and no Redis answers 503 until Redis is configured
  or the switch is off; a `tls_binding` middleware with no secret answers 503.
  Neither ever protected anything, so nothing is lost but a route that already
  misbehaved -- and a 503 that names the key is how the operator finds out.
- Behaviour changes without a refusal: a cors middleware with blank origins
  stops granting every origin; the wildcard presets stop sending credentials
  (browsers refused them); XFCC escaping changes the header bytes a backend
  parses, for values that needed it; `tls_binding` starts issuing and checking
  bindings, and refuses sessions over plain HTTP.
- Saves refused that used to succeed, each naming the field: Forward By without
  `by`, credentials with `*`, Redis storage without Redis, a per-middleware
  Cloudflare trust that disagrees, `tls_binding` on a plaintext entrypoint,
  turning on the global TLS Session Binding.
- `tls_binding` costs a response-writer wrapper and a SHA-256 of the client
  certificate per request on an mTLS connection; only routes that attach it
  pay, and only requests with a client certificate.
- The route service now runs every SaveGuard it is given (it ran only the
  first).

## Alternatives considered

- **An in-process revocation list.** No writer exists; it would be the inert
  switch again. A revoke API (and its RBAC, audit and dashboard page) needs a
  proto change and is left as an owner decision.
- **Serve revocation-without-Redis and warn.** A log line does not stop a token
  the operator believes revoked once Redis is added later and the route is not
  rebuilt; refusing names the dependency at the moment it matters.
- **Honour the per-middleware Cloudflare switch.** Two client identities per
  request and a trust boundary below the administrator; see T14.
- **Bind sessions to the TLS connection (exporter), issuing the binding on
  first sight.** That mints a binding for whoever presents a stolen cookie
  first -- the attack the middleware exists to stop -- and still dies on every
  reconnect.
- **Keep the global TLS Session Binding by reusing another global secret.** It
  would apply certificate binding to every route on every entrypoint, plaintext
  ones included: an outage for any deployment without mTLS everywhere.
- **Refuse stored configs for the save-only cases too.** Each degrades to what
  it always did, logged; taking routes out of service on upgrade would buy
  nothing.
