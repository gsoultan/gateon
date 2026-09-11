# Upgrading

Changes that alter behaviour on upgrade, newest first. Anything not listed here
is additive or internal.

Where a change can silently disable something that previously worked, gateon
also warns at startup naming the exact setting — you should not have to find it
here after the fact.

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

`ReputationIDFor` now pairs that client class with the client's network — /24 for
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
