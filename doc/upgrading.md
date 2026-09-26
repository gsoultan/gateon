# Upgrading

Changes that alter behaviour on upgrade, newest first. Anything not listed here
is additive or internal.

Where a change can silently disable something that previously worked, gateon
also warns at startup naming the exact setting — you should not have to find it
here after the fact.

---

## Unreleased

### The TC hook enforces the kernel management allowlist — **check `mgmt_whitelist_ips`**

On the TC hook, `enable_mgmt_whitelist` let every address reach the management
port: the program let listed sources through early and never dropped anyone
else. It now drops an unlisted source's packets to the management port, as the
XDP program always has. Separately, both programs read the port from the wrong
bytes of a packet that carried an IP option or was split into fragments, and
let it through; they now find the TCP header where the IPv4 header says it is.

**Who is affected:** an install on the TC hook with `enable_mgmt_whitelist` on.
Addresses not in `mgmt_whitelist_ips` lose the management port, as the setting
always said they would. Check the list before upgrading. The flag is still
never switched on against an empty list.

---

## v2.7.0

### Routes saved from the dashboard may be serving on every entrypoint — **check each route**

The dashboard sent a route's entrypoints as `entryPoints`; the gateway reads
`entrypoints`. Every route saved from the dashboard was stored with no
entrypoint restriction, and a route with none serves on **every** entrypoint —
so a route meant only for an internal listener was reachable on the public
one. The dashboard now sends the right key, but routes saved before this
release still have nothing stored. **What to do:** open each route whose
entrypoints matter and save it again, or check `entrypoints` in the API.

### Settings that were silently guessed are now refused — **a route may answer 503**

Several classes of configuration that used to run on a value nobody chose now
refuse the build, and a route whose security middleware or limit cannot be
built answers 503 and logs which one:

- A secret reference (`$env:`, `$vault:`, …) that cannot be resolved used to
  *become* the secret — an HS256 JWT secret of `$vault:…` was accepted. It now
  refuses the middleware, or startup for global settings.
- A boolean middleware setting strconv cannot read (`"yes"`, `"on"`, `"maybe"`)
  used to read as its default. Accepted spellings are `true`/`false`/`1`/`0`/
  `t`/`f` in any case; the dashboard only ever writes `true` and `false`.
- Rate limits, in-flight limits, body-size buffering and WASM were served
  *without* when they failed to build. They now fail closed with the other
  boundaries.
- Circuit breaker `error_threshold` outside (0, 1], `min_requests` below 1
  and non-positive windows, a `security_headers` preset that is not one of
  `legacy`, `recommended`, `strict` or `none`, and `file_security` with
  `enable_clamav` on and no ClamAV address anywhere (it scanned nothing).

**Who is affected:** only configurations with such a value, which were not
doing what they said. The log line names the middleware and key.

### Proxied pages no longer get the dashboard's security headers — **attach `security_headers` where you relied on them**

Every HTTP entrypoint applied the dashboard's *recommended* header preset to
every response it served, so a proxied page that sent no CSP of its own got the
gateway's: `script-src 'self'` (inline and CDN scripts blocked), fonts and
images from its own origin only, `form-action 'self'` (a login form posting to
an identity provider blocked), `frame-ancestors 'none'`, plus HSTS with
`includeSubDomains` pinning every subdomain to HTTPS for a year. Web
applications with any third-party asset broke behind the gateway. Proxied
responses now carry the headers their backend sends and no others; the
dashboard and management API keep their own. **What to do:** a route that
wants gateway-added headers attaches a `security_headers` middleware and picks
a preset — *legacy* for the low-risk set, *recommended* or *strict* for a CSP
you have checked against the application.

### Rate limits apply as configured — **effective limits halve**

The limit was scaled by reputation/50 on the belief that a neutral score was
50; a client with no history scores 100, so every well-behaved client got
twice the configured rate and burst. The login limiter (5 a minute) was 10.
The `ja4h` and `fingerprint` strategies are now scoped to the client's
network, and `tenant` falls back to the client address for a request with no
tenant instead of not limiting it. **What to do:** if you tuned a limit by
observation, it may now be half what you expect.

### Response body rewrites start applying — **check every `transform` middleware with a response search**

The transform middleware's response rewrite never applied to proxied traffic:
the reverse proxy flushes after every write, and the middleware took any flush
as a stream and passed the body through untouched. With a content-type filter
set, a GET was skipped before its response was even seen. Rewrites configured
long ago, and never observed working, now take effect. The backend is also
asked for plain bytes on such routes (no `Accept-Encoding`), so a compress
middleware in front does the compressing. Error responses, streams (SSE, gRPC)
and encodings the gateway cannot decode are still passed through untouched.

### `GATEON_TRUST_CLOUDFLARE_HEADERS` now works — **an allowlist of Cloudflare addresses stops matching**

The variable was ignored whenever the config file had a WAF section, which it
always does, so every client behind Cloudflare appeared as a Cloudflare edge
address. Requests from Cloudflare's ranges are now attributed to
`CF-Connecting-IP`. **Who is affected:** an install that set the variable and,
seeing edge addresses anyway, allowlisted Cloudflare ranges in
`GATEON_MANAGEMENT_ALLOWED_IPS` or an IP filter — list client addresses
instead. A Cloudflare Tunnel is unaffected unless its address is in
`GATEON_TRUSTED_PROXIES`; see [management-entrypoint.md](management-entrypoint.md).

### A route's own WAF inspects responses — **may start refusing responses**

A route WAF with `dlp=true` never turned on the response phase, so it passed
every leak; and a route with its own WAF skips the global one, so it lost the
global WAF's response DLP. Route WAFs now inspect responses when DLP is on,
and inherit the global WAF's DLP (its flag or the enterprise tier) unless the
route sets `dlp=false`. Expect the response-phase cost on those routes.

### JA4 fingerprints are the specification's — **fingerprint-keyed state resets**

GREASE values were hashed in, so Chrome's JA4 changed on nearly every
connection, and the format matched nothing else that computes JA4. Reputation
scores, mitigations and threat records keyed on the old values stop matching
and age out. `ebpf.xdp_ja4_blocklist` is removed (field 12 is reserved): the
kernel lookup compared the ClientHello's random bytes with a hash of the
fingerprint and never matched. Fingerprints are enforced at L7.

### Kubernetes routes follow their objects — **routes that lingered are removed on the first sync**

- A path or match removed from an Ingress or HTTPRoute now removes its route.
  Sync used to only add and update, so a removed path kept routing to its old
  backend until the whole object was deleted; after upgrading, the first sync
  of each object (within the 30-second resync) removes what it no longer asks
  for.
- An HTTPRoute with several hostnames now routes each of them. Its rule was
  ``Host(`a`, `b`)``, which the router read as one literal host that no request
  carries, so such a route served nothing.
- HTTPRoute method and exact-header matches are now enforced. They were
  dropped, so a route meant for requests carrying a header took every request
  on its path — expect such routes to match less. Regular-expression header
  and query matches, which the rule language cannot express, skip the match
  and log it rather than widen the route. A rule with no matches routes
  everything under `/`, as the Gateway API defines; it produced no route.
- With the chart's `watchNamespace`, the controller now lists only that
  namespace (`GATEON_K8S_WATCH_NAMESPACE`). It listed every namespace, which
  the namespaced Role refused, so a namespace-scoped install synced nothing.

### A client can no longer choose the certificate the gateway presents to a backend — **set the match header on the route**

A service whose `tls_client_config` selects its client identity `BY_HEADER`
read the header from the client's request, so a client that sent the header
chose the identity the gateway authenticated to the backend as. The match
headers are now the gateway's: a client's copy is removed when the route is
entered, and only the route's own middlewares — a claim mapping, forward-auth's
`auth_response_headers`, a `headers` rule — can set one. If something in front
of the gateway set the header, set it on the route instead. The backend no
longer receives the client's copy either.

Also fixed in the same feature: `BY_HOST` chooses by the host the request was
routed on (it read `X-Forwarded-Host`); identities without an `id` no longer
share one certificate; WebSocket and other upgrades present the selected
certificate (they presented none). See ADR-0014.

### CORS is decided per route — **a backend's own CORS headers now reach the browser**

The HTTP entrypoint answered every CORS preflight itself, before a route was
chosen, with a permissive policy that never allows credentials, and added
`Access-Control-Allow-Origin` to every response. It no longer does (ADR-0015):

- A route's `cors` middleware now receives its preflights, so a policy that
  allows credentials works for requests that need a preflight. Origins it
  refuses are refused on the preflight too.
- On a route **without** a `cors` middleware, preflights and responses go to
  the backend. Its own CORS headers are sent to the browser as it wrote them —
  they used to go out beside the gateway's as a second
  `Access-Control-Allow-Origin`, which browsers reject. Where its answer
  carries no CORS headers, the gateway supplies the same permissive,
  credential-free default as before.
- That default cannot tell a backend that does not do CORS from one that
  refused an origin by leaving the header off, so it grants such an origin
  non-credentialed access, as before. **To refuse origins, attach a `cors`
  middleware** -- with your allowlist, or, when the backend enforces its own,
  with `preset: backend`, which leaves CORS entirely to the backend: nothing
  answered, added or stripped.
- A `cors` or `grpcweb` middleware whose `preset` names no preset is refused.
  It was ignored, and the empty lists it left allowed every origin, so a
  misspelt `restricted` allowed anyone. Check stored middlewares for typos.
- Refusals made before a route is chosen — IP or user mitigation, the global
  GeoIP block and honeypot, the connection limit — no longer carry CORS
  headers; browsers show them as CORS errors.
- `management.cors` now answers preflights to the management API on every
  entrypoint that serves it.

### Route names are unique, and per-route state is kept per route — **rename routes that share a name**

- Saving a route whose name another route already has is refused (the API
  answers 400; config import imports the first and reports the rest). Routes
  that already share a name keep working, and the gateway logs a warning
  naming them once: their metrics, access logs and threat records are
  reported together until all but one is renamed.
- Circuit breakers and Redis cache entries were kept per route *name*, so two
  routes with the same name shared a breaker (one failing backend opened the
  other route's circuit) and answered from each other's cached responses.
  They are now kept per route ID. Redis cache keys change, so the Redis cache
  starts empty after upgrading.
- The Redis rate limiter kept one window per client for every route and every
  rate-limit middleware, so traffic to one route counted against another's
  limit. Windows are now per route and middleware; each route gets its
  configured limit, and the old windows are discarded.
- Routes generated from Kubernetes Ingress paths and HTTPRoute matches get
  names of their own (`k8s/<ns>/<ingress>/<rule>/<path>`,
  `k8s-hr/<ns>/<route>/<rule>/<match>[/<host>]`); they shared their rule's
  name. Metrics and dashboards keyed by the old names need updating.

### TLS settings saved from the dashboard apply without a restart

Saving settings from the dashboard (`PUT /v1/global`) stored them and applied
almost nothing: it skipped what the API's `UpdateGlobalConfig` applies. It now
runs the same code, so TLS, alerting, IP reputation, retention, eBPF port
knocking and a generated audit signing key all apply when saved, and the audit
entry records the caller's address.

For TLS specifically:

- Turning ACME **off** takes effect: the startup TLS config had ACME's
  certificate source fixed into it, so ACME kept answering until a restart.
- Turning ACME **on** also offers `acme-tls/1`, so TLS-ALPN-01 validation
  works, and domains added to `tls.domains` are authorised at once.
- The minimum and maximum TLS version, the cipher suites and the
  client-certificate mode apply to the next handshake.
- A route that names its own certificates is served them even where global
  ACME covers its host; ACME answered first. With ACME on and certificates
  configured too, a host ACME does not cover is served a configured
  certificate instead of failing the handshake.
- Changing the ACME **email or CA server** applies to the next certificate
  ordered, and certificates already issued are renewed with the new settings.
  The previous ACME manager is retired rather than dropped: its scheduled
  renewals cannot be cancelled, so it is cut off from its CA instead. An
  existing ACME account keeps the contact it registered with; the CA does not
  update it.

### One access log line per request, with the client's address

On an entrypoint with access logging on, every routed request was logged
twice: once by its route (`route=<route name>`) and again by the entrypoint
(`route=gateon-<entrypoint>`). The route's line is now the only one; the
entrypoint logs only requests no route took (404s, refusals made before
routing). Anything counting requests from access logs counted double.

Each line also carries `client`, the client's address as the entrypoint
resolved it under your trusted-proxy settings. `remote_addr` is still the TCP
peer, which behind a load balancer is the balancer.

### Behaviour that now does what it was configured to do

- **Plain HTTP on a TCP entrypoint:** event streams and WebSockets were cut
  at the entrypoint's write timeout (15 seconds by default); they now run as
  on an HTTP entrypoint, and the timeouts are read per request, so a change
  applies without a restart. Cleartext HTTP/2 -- gRPC without TLS -- is served
  there too; it was refused.
- **Load balancing:** services saved from the dashboard as least-connections
  or weighted were running round robin; they now use their policy. A weighted
  service whose targets have no weights serves them equally instead of 502.
- **Retry:** the retry middleware retried nothing. It now retries idempotent
  methods on a 502/503/504 or transport error, up to `attempts`.
- **Circuit breaker:** half-open admits one probe instead of everything,
  `min_requests` defaults to 20 instead of 0 (one 5xx opened it), and
  `Retry-After` is the time left rather than 30.
- **Headers middleware:** response rules are applied after the backend's
  headers, so a rule now overrides the backend instead of being overwritten.
- **API keys and basic auth** are held to the route's roles and scopes.
- **mTLS:** a request whose `Host` names a different mTLS route than the one
  its handshake was for is refused.
- **gRPC-Web** no longer grants credentials to any origin, and the
  *Restricted* CORS preset with no origins restricts instead of allowing all.
- **IP filters:** a bare IPv6 address is one host, not a /32.
- **Security headers:** the *None* preset sets nothing (it fell through to the
  legacy set, overwriting the backend's own headers); the legacy set, which an
  unset preset means, now sends `X-XSS-Protection: 0` instead of asking for the
  browser XSS auditor; and a misspelt preset refuses the build.
- **TCP entrypoints:** plain HTTP arriving on a TCP entrypoint now passes the
  global honeypot, GeoIP country block and per-IP connection limit, which the
  HTTP entrypoint always applied and this path skipped.
- **Metrics:** a request is counted once in path, domain, country, protocol and
  per-IP statistics — it was counted by the entrypoint and again by its route,
  so anomaly detection saw clients at twice their rate. A `metrics` or
  `accesslog` middleware attached with no name of its own now does nothing
  (every route already measures and logs itself); give it a name to record a
  separate view.
- **Forwarded scheme:** a route's `forwardedheaders` forced scheme now wins over
  a trusted proxy's `X-Forwarded-Proto` — the case it exists for — so its
  redirects, Secure cookies and upstream `X-Forwarded-Proto` follow it.
- **Custom error pages** arrive whole: they kept the backend's Content-Length
  and Content-Encoding, which cut them short or announced them as gzip. SSE and
  websockets on routes with the errors middleware now work.
- **Compression** leaves responses under `min_response_body_bytes` alone; the
  minimum was ignored, most of all behind the proxy.
- **ACME on a route** works without the global ACME switch; such routes'
  handshakes failed with "ACME not initialized". The settings page no longer
  offers DNS-01, which the gateway never ran.
- **Canary API:** `POST /v1/services/canary` answers 400 with a reason for a
  service whose policy ignores weights (anything but weighted round robin), a
  missing service, or weights naming none of its targets. It used to report
  success and do nothing.
- **Buffering:** a body over `max_request_body_bytes` is answered 413 and never
  reaches the backend. It was forwarded anyway and came back as a 502 counted
  against the backend.
- **Bot management:** challenge passes issued before the upgrade are not
  accepted (the seed was its own pass); visitors are challenged once more.
- **Postgres** sessions run in UTC, so TTLs no longer drift with the host's
  zone.
- **Service health-check thresholds and WASM modules** survive a restart on the
  database-backed stores (migrations 63 and 64 add the columns).
- **The management database** is created `0600`, and systemd keeps the state
  and config directories private.
- **The dashboard's Metrics page** moved to `/metrics-dashboard`, off
  `/metrics`, which Prometheus answers — a bookmark or reload of the old path
  showed exposition text. Update bookmarks.

### The setup wizard's SQLite database must be a file in the data directory

During first run the wizard's database step — `POST /v1/setup`, and its "Test
connection" button, `POST /v1/setup/test-db` — opens the database it is given
before anyone has signed in. A SQLite url there could reach any file the
gateway can write: opening it created the file, or narrowed the permissions of
one that existed; a `?_pragma=` query ran as SQL when the database opened, and
could `ATTACH` a database anywhere; and SQLite percent-decodes a `file:` URI
after any check on the string, so `..%2F` climbed out of a directory. The
wizard now takes a SQLite database only as a plain file path inside the data
directory — no query string, no `file:` URI — and answers anything else with
`400`.

**Who is affected:** an install that runs the wizard from a working directory
outside its data directory (`GATEON_DATA_DIR`; otherwise `/var/lib/gateon` on
Linux when it exists, otherwise the working directory), where the default
`gateon.db` resolves outside it. The packaged unit and image run from
`/var/lib/gateon`. Give the wizard an absolute path inside the data directory,
or set the url in `global.json`: a database the operator configures on disk is
not restricted.

### `mysql://` and `mariadb://` are refused at startup — **they never worked**

`Open` accepted both schemes, and most migrations carry a `DriverMySQL` branch,
but none of it has ever run. Migration 2 puts `host TEXT` and `path TEXT` in a
`PRIMARY KEY`, which MySQL rejects outright:

```
Error 1170 (42000): BLOB/TEXT column 'host' used in key specification without a key length
```

A fresh install fails on the *second* migration, so no MySQL or MariaDB database
has ever reached the third — at any version. Repairing that one statement does
not help: **43 of the 62 migrations fail on a real MySQL server**, most of them
on `ADD COLUMN IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS`, which MySQL does
not support, and on `DEFAULT` values attached to `TEXT` columns, which it
forbids. The branches are not untested, they are written in a dialect MySQL does
not speak. CI has never had a MySQL target, which is why this stood.

Both schemes are now refused by `Open` with an error naming the supported
engines, and the MySQL driver is no longer linked into the binary.

**Who is affected:** nobody with a working deployment, because there is no
working MySQL deployment to have. A configuration carrying a `mysql://` DSN was
already failing at startup; it now fails with an error that says why, before the
connection is attempted, and without echoing the DSN — and therefore its
password — back into the log.

**What to use instead:** SQLite for a single node, Postgres for anything
multi-node. Both are exercised on every commit by
`TestUpgradeFromShippedReleaseKeepsData`.

---

## v2.6.1

### Session revocation reaches every instance, when Redis is configured

Disabling, deleting, demoting or changing the password of an account has always
ended its sessions immediately on the instance that handled the request, and
left the others serving the cached binding until it expired — up to 30 seconds.

Revocations now publish on `gateon:config:invalidation`, the channel that
already carries route, TLS and WAF invalidations, so a healthy multi-instance
deployment converges in a round trip.

**Who is affected:** nobody has to do anything. With Redis configured you get
the faster path automatically. **With no Redis — the default, and every
single-instance deployment — nothing changes:** the 30-second binding TTL
remains the whole mechanism, which is deliberate, because Redis pub/sub is
at-most-once and a dropped message would otherwise restore unbounded staleness.

One related fix ships with it: node identity for *all* invalidation types moves
from the hostname to a per-process value. The listener discards messages whose
node id matches its own, so two gateon processes on one host — an ordinary
container arrangement — were discarding each other's route, TLS and WAF
invalidations as self-broadcast. If you run more than one instance per host,
those now propagate where they previously did not.

See [ADR 0012](adr/0012-session-revocation-propagates-but-expiry-guarantees.md).

### Server-Sent Events now stream through the honeypot and deception middlewares

Both wrap the response writer, and neither re-exposed `Flush`. Wrapping
`http.ResponseWriter` promotes only `Header`, `Write` and `WriteHeader`, so a
wrapper silently stops being an `http.Flusher` — and an SSE response behind
either middleware buffered in `net/http` until the upstream closed, then arrived
complete and far too late.

**Who is affected:** anyone running a route with `honeypot` or `deception`
enabled that also serves SSE. The data was never wrong; it arrived at the end
instead of as it was produced, which reads as a dead feed rather than a
middleware bug.

Both middlewares already forwarded `Hijack`, so WebSockets were unaffected
throughout. If you worked around this by taking a route off one of these
middlewares, you can put it back.

### The first-run setup wizard can test a database connection

`POST /v1/setup/test-db` — the wizard's "Test connection" button — answered
`503` before setup completed and `403` afterwards, so it could not succeed in
any state. It is now reachable during first run, which is the only window it is
permitted in.

### Removing a setting from a config file now takes effect

`global.json` and `routes.json` were merged into what was already loaded, so a
deleted key or route survived a re-read. This is behaviour-identical today —
the files are read once at startup and nothing watches them — and is listed
only because the semantics changed: a read now reflects the file as written
rather than accumulating across reads.

---

## v2.6.0

### Every session ends on upgrade — **everyone signs in again**

Management sessions are PASETO tokens. They now carry an `sb` claim: a digest
over the account's password hash, role and disabled flag, recomputed and checked
on every request. Tokens minted before this change carry no `sb` and are refused
by design.

This is what makes revocation work at all. Disabling an account, deleting it,
changing its password or changing its role previously wrote to a row that no
authenticated request ever read — an operator disabling a departing employee set
a column and changed nothing, and a demoted administrator kept `role=admin`
until the token expired on its own. All four now end the session immediately.

Token lifetime also drops from 24 hours to 8.

**Who is affected:** everyone holding an open dashboard session or a stored
bearer token, once. Scripts using a long-lived token must re-authenticate.

**Multi-instance caveat:** the binding is cached per process with a 30-second TTL
(`GATEON_SESSION_BINDING_TTL`). A revocation is immediate on the instance that
performed it and takes up to that long to reach the others. See
[ADR 0005](adr/0005-session-lifecycle-and-first-run-trust.md).

### Data-leak rules now run against compressed responses — **may start refusing responses**

Response-phase DLP had matched nothing on real traffic since the gwaf migration,
and reported every response clean while it did.

`httputil.ReverseProxy` forwards the client's `Accept-Encoding` verbatim, and
Go's `http.Transport` decompresses transparently only when it set that header
itself. Every browser sends `gzip, deflate, br`, so the origin compressed and the
engine was handed a DEFLATE stream. There is no grammar in a DEFLATE stream: no
rule matched, nothing was recorded, and the browser decompressed and painted the
card number.

The encoding is now negotiated down to something this build can decode, and the
held body is inflated once under a cap for inspection while the origin's own
bytes are forwarded untouched — so client compression and `Content-Length` both
survive. An encoding that still cannot be read is counted as **uninspected**,
never as clean.

**Effect: rules that fired on nothing now fire on real traffic, and `dlp_action`
defaults to `block`.** A response carrying something the corpus recognises — a
card number by issuer range and Luhn, a cloud or SaaS credential, a private key,
a database URI with an embedded password, a stack trace or database error from
the origin — is refused rather than served.

**Who is affected:** the enterprise tier, where DLP and response inspection are
on by default; and any tier where `waf.dlp` is explicitly `true`, because an
explicit opt-in upgrades response inspection along with it.

**Who is not:** minimal and standard tiers without that opt-in. Response
inspection stays off there, as it always was.

Set `dlp_action` to `audit` for one release and read
`gateon_middleware_waf_would_block_total{route,rule_id,phase}` before letting it
refuse anything — that counter is what makes audit mode a measurement rather
than an off switch. `redact` forwards the response with the finding replaced.
See [ADR 0008](adr/0008-response-inspection-must-control-its-own-encoding.md).

### Connect and gRPC now enforce authorization — **a role that worked over gRPC may now be refused**

The management API is reachable over REST, Connect and gRPC, and all three end at
the same methods. Authorization existed on one of them: `RequirePermission` takes
an `http.ResponseWriter`, so it could not be called from a Connect or gRPC
handler — and dropping a check with that signature does not fail to compile.

A viewer was refused by `POST /v1/diagnostics/mitigate` and accepted by
`/gateon.v1.ApiService/MitigateThreat`. Because `HandleProxyOrLocal` dispatches on
`Content-Type` before the mux is consulted, any authenticated principal of any
role could reach every RPC by sending `application/grpc-web`. The escalation was
selectable by a request header.

One permission table now backs both interceptors, unmapped procedures are denied,
and a test reflects over the generated handler interface so a new RPC fails the
build rather than shipping unguarded.

**Who is affected:** any client that relied — knowingly or not — on a non-REST
transport reaching a method its role cannot call over REST. Separately, the read
routes that had no check at all (`/v1/routes`, `/v1/services`, `/v1/middlewares`,
`/v1/tls-options`, `/v1/certs`, `/v1/entryPoints`, `/v1/traces`,
`/v1/cloudflare-ips`) now require the permission their RPC twin requires. See
[ADR 0006](adr/0006-transport-neutral-authorization.md).

### Middleware credentials are masked for callers who cannot write them

A middleware's config is a `map[string]string`, and for the auth middlewares the
values in it are credentials: `secret` for jwt, hmac and pow, `password` and
`users` for basic auth, `client_secret` for oidc. The list endpoints returned
those maps exactly as stored, and `RoleViewer` — the lowest role there is,
read-only by definition — holds read on middlewares.

That is not a configuration disclosure. For jwt and hmac the value is the signing
key for a route the gateway is protecting, so whoever holds it can mint a token
the gateway will accept: a read-only dashboard account was access to the backend
as any user. `users` is worse in the small — it is `alice:pw1,bob:pw2`, every
basic-auth password in one string.

Credentials now come back as a placeholder for any caller who cannot already
write them. Write permission is the right line, because someone who can set the
secret gains nothing by reading it.

**Who is affected:** tooling that reads middleware secrets through a viewer or
operator token. Config export is unchanged for admins, so backup flows still
round-trip.

### Route selection resolves dot segments and normalises host spellings — **a request may now match a different route**

Both are bypass fixes, and both change which route — and therefore which
middleware chain — a request gets.

`/public/../admin` used to select `/public`'s routes. Selection walked the path
one segment at a time and treated `..` as an ordinary segment name; there is no
child node named `..`, so the lookup stopped at the `/public` node. Nothing
upstream resolved it first — Go's HTTP server leaves `r.URL.Path` exactly as the
client sent it — and the proxy joined that same string onto the backend URL,
where nginx, Apache and most frameworks *do* resolve it and serve `/admin`. The
gateway ran `/public`'s chain while the backend returned `/admin`'s content, so
if `/admin` carried authentication and `/public` did not, it did not run. The WAF
was not a mitigation: it is itself middleware on the route that was chosen.

Paths are now resolved in `SelectRoute`, where both callers converge.
`r.RequestURI` keeps the original, so the WAF and the access log still see what
was actually sent.

Separately, `app.example.com.` and `app.example.com` are the same host — the
trailing dot is the DNS root label, and clients, proxies and health checkers do
send the fully-qualified spelling. Routing compared strings, so a fully-qualified
host missed its own host trie *and* any wildcard covering it, and fell through to
whatever host-agnostic route the deployment had. It found the wrong route, not no
route. `NormalizeHost` is now applied on both sides — where the keys are built and
where they are looked up.

**Who is affected:** any deployment whose routes overlap once paths are resolved,
or that mixes host-scoped and host-agnostic routes. The already-clean case, which
is all real traffic, costs a byte scan and no allocation.

### Reputation, rate limiting and proof-of-work key on network + client class — **accumulated scores reset**

`ReputationBlocker` is appended to every route's chain unconditionally and
refuses with 403 below a score of 2.0. It keyed that score on the JA4+
fingerprint, which is the TLS stack plus the shape of the HTTP headers: method,
version, cookie-present, referer-present, header count, header-name mask,
Accept-Language. It reads no address, no connection and no credential. It names
the software making a request and was never capable of naming the party making
it.

Two people running the same Chrome build in the same language produce the same
fingerprint. So one patient attacker on an unmodified browser could drive that
shared score to zero, and every other user of that browser was then refused on
every route — no volume required, the attacker's entire advantage being that they
looked ordinary. The inverse was equally invisible: a client that varies its
headers gets a fresh identity per request and never accumulates a score at all.
The same identity ran the adaptive rate limiter, the proof-of-work difficulty
gate and its challenge id, the tarpit, and deception's troll threshold.

`repid.For` now pairs that client class with the client's network — /24 for
v4, /64 for v6, the narrowest scope that still survives a phone changing cell or
a DHCP lease renewing.

**Effect:** scores accumulated under the old key no longer resolve, so reputation
starts from neutral on upgrade. Blocks that were mass false positives stop;
blocks that were correct have to re-earn themselves. Honeypot bans now escalate
(15m → 1h → 6h → 24h) instead of landing flat at 24 hours, because the trap makes
one hit strong evidence about the *request* while the ban lands on an *address*,
and addresses are shared. See
[ADR 0011](adr/0011-reputation-is-scoped-to-a-network.md).

### `redis.enabled` and `otel.enabled` are now honoured — **may disconnect Redis or stop traces**

Both flags were read by nothing. Redis connected because `redis.addr` was set,
and traces exported because `otel.endpoint` was set; the dashboard toggles
changed nothing either way.

They now gate their subsystems, which is what the dashboard has always claimed.

**Who is affected:** a hand-written `global.json` that sets an address or
endpoint *without* also setting the flag. That deployment works today and stops
after upgrading.

**Who is not:** configs saved through the dashboard (it writes the flag
explicitly), and deployments configured with the `REDIS_ADDR` or
`OTEL_EXPORTER_OTLP_ENDPOINT` environment variables — those still enable their
subsystem on their own, since setting one is an unambiguous instruction with no
flag to contradict it.

```jsonc
// before — worked
"redis": { "addr": "redis:6379" }

// after — set the flag
"redis": { "enabled": true, "addr": "redis:6379" }
```

proto3 cannot distinguish an unset bool from an explicit `false`, so there is no
migration that could tell "never set it" from "turned it off". gateon logs a
warning at startup for exactly this shape.

### Generic XDP is refused unless `ebpf.allow_generic_xdp` is set

If the driver rejects a native XDP attach, gateon no longer silently falls back
to generic (SKB) mode. Generic XDP runs after the `skb` is allocated, so it drops
no earlier than a firewall rule while still charging every passed packet the full
program cost — on a jumbo-MTU NIC it is slower than running no eBPF at all.

**Who is affected:** anyone whose eBPF was silently running in generic mode —
which on a default EC2 instance is everyone, because the ENA driver refuses
native XDP above a page-sized MTU (the VPC default is 9001) and unless the
driver is using at most half its queues.

The refusal is logged with the specific reason and the remediation commands.
Preferred fix on a virtualized NIC is `ebpf.tc_filtering = true`, which attaches
at the clsact hook and carries none of generic XDP's per-packet cost. Setting
`ebpf.allow_generic_xdp = true` restores the old behaviour.

### `make build` and `make release` now include eBPF

`HAS_EBPF` probed for a filename `bpf2go -target bpf` never emits, so the
wildcard never matched and both targets compiled the `noebpf` stub — while the
Dockerfile's plain `go build` compiled eBPF in. The two paths produced different
binaries.

**Effect:** binaries from `make release` now contain a subsystem the previous
ones did not. Combined with the change above, an eBPF-enabled config that
appeared inert may now attach — or refuse, with a logged reason.

### Bot-challenge secret is no longer a published constant

When `waf.bot_management.secret_key` was unset, challenge tokens were signed with
a literal compiled into the source. Anyone who read the repository could forge a
valid clearance token for any user agent and address and bypass the JS challenge
and browser integrity check.

The fallback is now 32 random bytes per process.

**Effect:** with no secret configured, tokens do not survive a restart and are
not shared between instances, so clients are challenged again. Set
`waf.bot_management.secret_key` to avoid that. This is a reason to configure a
secret, not a reason to keep shipping one everybody has.

### HA heartbeats and gossip require `ha.auth_pass`

HA adverts were unauthenticated: any host that could reach the port could make
the master release its virtual IP with one forged datagram. Gossip likewise ran
memberlist with no `SecretKey`, and arriving messages are applied to IP
reputation, which decides who gets shunned.

Both now authenticate with `ha.auth_pass`, and **refuse to start without it**.

**Effect:** HA and gossip do not run until `ha.auth_pass` is set to the same
value on every node. Clusters must be upgraded together — an upgraded node
rejects a legacy peer's adverts as malformed — and during a rolling upgrade both
halves may claim the VIP, so drain the passive node first.

### Removed configuration

All tags are `reserved`, so nothing can silently reuse them. Each of these was
read by no code; removing them changes no behaviour.

| Setting | Why |
| :--- | :--- |
| `geoip.xdp_geofencing` | wrote to a map no BPF program read; geofencing works via MaxMind and was never affected |
| `acme.dns_provider`, `acme.dns_config` | ACME here is autocert, which has no DNS-01 support at all |
| `gitops.ssh_private_key` | only go-git's HTTP transport is imported; SSH needs a host-key story first |
| `waf.rules_url`, `waf.update_interval_hours` | the rule downloader was retired with the gwaf engine change |
| `anomaly_detection.prometheus_url` | detection reads a local aggregator by design, not an external Prometheus |
| `anomaly_detection.anomaly_retention_days` | anomalies are never persisted, so there is nothing to retain |
| `debugger.max_captures` | there is no in-memory capture list to bound |
| `management.enable_port_knocking`, `management.port_knocking_sequence`, `management.xdp_management_whitelisting` | duplicates of the `ebpf.*` settings that do work |
| `auth.oidc` and all of `OidcConfig` | dashboard SSO was never built; **per-route OIDC is separate and unaffected** |
| all of `titan` | seven dashboard toggles controlling nothing; the phantom core still runs |
| `ebpf.xdp_cuckoo_filter` | nothing populated the map, while both programs looked it up per packet |

`waf.auto_update_rules` is kept but **relabelled** in the dashboard: it no longer
updates anything and means "load custom rules from `<data_dir>/waf/rules`".

### Diagnostics: `cuckoo_filter_entries` → `shunned_ip_count`

The field was populated with the shunned-IP count while the cuckoo map was
always empty, so the dashboard reported one number under another's name. The
value was real; only the label was wrong.

---

## v2.5.2

### Route, service and entrypoint configuration moved into the database

Until v2.5.1 the five configuration registries — routes, services, entrypoints,
middlewares and TLS options — were read from `routes.json`, `services.json`,
`entrypoints.json`, `middlewares.json` and `tls_options.json` on every start.
From v2.5.2, **a deployment with a management database reads all five from that
database instead**, and the files are consulted exactly once, to seed a store
that is still empty. The selection is in `cmd/gateon/main.go`: a database-backed
store when `authManager.DB()` is non-nil, the file-backed registry otherwise.

**Who is affected:** anyone with auth configured, which is everyone who has
completed setup — auth is what creates the database. After the first start on
v2.5.2 or later, **editing `routes.json` changes nothing**. The dashboard and
the API are the source of truth; the file is an import format, not a live one.

**Who is not:** a deployment running with no management database at all. It
stays on the file-backed registries, unchanged.

This matters most for config managed outside gateon. A pipeline that templates
`routes.json` and restarts the process was, before this change, the whole
mechanism; afterwards it silently stops applying and the last-imported set keeps
serving. Export the current configuration from the dashboard before you upgrade,
so you can tell what the import produced.

### Do not stop on v2.5.2 or v2.5.3 — upgrade straight to v2.6.1

The import described above (`seedConfigFromFiles`) **did not ship until v2.6.0**.
In v2.5.2 and v2.5.3 the database-backed stores start empty and nothing copies
the files into them, so a file-configured deployment comes up with no
entrypoints, no routes and no services, and answers nothing.

The fix is in v2.6.0 and the only safe path is to skip the two releases that
have the gap. Upgrading from anything at or below v2.5.1 directly to v2.6.1
imports correctly, because the seeding step runs against stores that are still
empty — which is exactly the state those releases leave them in, so a deployment
that already stopped on v2.5.2 recovers by upgrading rather than by restoring.

---

## v2.2.2

### An account with no role becomes a viewer

Migration 52 runs `UPDATE users SET role = 'viewer' WHERE role IS NULL OR role
= ''`, giving every account an explicit role. A blank string is not a role any
permission check knows how to answer, and the safe reading of one is the least
privileged.

**Who is affected:** any deployment with an account whose role was blank. It
becomes read-only. Nothing is escalated — `viewer` is the lowest role there is —
but an account someone was using as an administrator can stop being able to
write. Check the user list after upgrading and set the intended role.

---

## v2.2.1

### Six-digit WAF rule ids gained a leading `1` — **custom rule ids change**

Migration 51 rewrites every `waf_rules` row whose id is exactly six digits and
starts with `9`, `1` or `2`, prefixing it with `1` and rewriting the matching
`id:` inside the rule's directive text so the two stay consistent. The reason is
collision: the shipped rules occupied the same six-digit space as the OWASP core
rule set.

**Who is affected:** anyone who wrote custom rules in that range — the `WHERE`
clause does not distinguish gateon's own rules from an operator's. A rule
authored as `900123` is `1900123` afterwards. Anything that names a rule id
outside the `waf_rules` table does **not** get rewritten with it: dashboard
filters, alert routing, SIEM correlation rules and per-rule exceptions all keep
pointing at an id that no longer exists, and silently stop matching.

Inventory your custom rule ids before upgrading, and re-point whatever refers to
them afterwards.

---

## v2.2.0

### JA3 is gone; JA4+ replaces it

Migration 50 removes the `ja3` column from `security_threats` and `traces` on
Postgres and MySQL, and blanks it to the empty string on SQLite, where dropping
a column is not practical. JA4+ had already replaced it everywhere that reads a
fingerprint.

**Who is affected:** anything querying the database directly for `ja3` —
a Grafana panel, an export job, a retention script. Historical JA3 values are
**not** recoverable after this runs; there is no backfill, because JA4+ cannot
be computed from a stored JA3. Export anything you need first.

Note that the migration ignores errors from both statements by design, so it is
recorded as applied whether or not the column was there to remove.

---

## Upgrading from v1.5.x

There is no per-release note between v1.5.0 and v2.2.0. The sections above cover
the changes in that span that are visible in the schema, the configuration
contract or the startup path, which is what a mechanical comparison of the two
releases can establish; they are not a complete behavioural history of the forty
releases in between.

What has been verified for that jump:

- The migration chain is **append-only**. v1.5.0 ends at migration 30, and all
  thirty still carry the same ids and names, with no change to what they do —
  so the chain from 31 onward applies to a v1.5.0 database in order and lands on
  the same schema a fresh install has.
  `TestUpgradeFromShippedReleaseKeepsData` rehearses this with data in the
  tables, on SQLite and Postgres.
- **No configuration setting changed its name, type or field number.** Settings
  removed since v1.5.0 are listed under v2.6.0; all were read by nothing.
  A v1.5.0 `global.json` therefore still parses, and unknown keys are ignored
  rather than rejected.
- **Only SQLite and Postgres are real backends**, and the other two are now
  refused rather than accepted and failed on. See the Unreleased section above.

Migrations have no `Down`. There is no rollback, so take a backup of the
database before starting; restoring it is the only way back.
