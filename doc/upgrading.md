# Upgrading

Changes that alter behaviour on upgrade, newest first. Anything not listed here
is additive or internal.

Where a change can silently disable something that previously worked, gateon
also warns at startup naming the exact setting — you should not have to find it
here after the fact.

---

## Unreleased

### "Enable Revocation" now checks revoked tokens for JWT, PASETO and OIDC, and needs Redis

**Read this before upgrading if any `auth` middleware has `enable_revocation: "true"`.**

The switch was offered for JWT, PASETO and OIDC but only JWT read it, and only with
Redis configured. A PASETO or OIDC route kept accepting a token whose `jti` you had
written to Redis; a JWT route with the switch on and no Redis checked nothing.

- All three now refuse a verified token while the Redis key
  `<revocation_prefix><jti>` exists (default prefix `revoked_jti:`), with `401
  token revoked`. A Redis lookup that fails refuses the request (`401 token
  revocation status unavailable`), as JWT already did. A token with no `jti`
  cannot be revoked by this list.
- **With the switch on and no Redis configured, the middleware no longer builds:**
  saving it is refused ("revocation needs Redis: ..."), and a stored one makes its
  routes answer `503` until Redis is configured (Settings > Redis, then restart) or
  the switch is turned off. Nothing could ever have been revoked on such a route --
  the gateway has no other place to be told a token is revoked.
- Required scopes are now read as the form shows them: separated by commas, spaces
  or both (`read, write` and `read write` both mean two scopes). Required roles are
  separated by commas and trimmed. A list typed with spaces after its commas used
  to refuse every valid token.

**Who is affected:** JWT/PASETO/OIDC auth middlewares with Enable Revocation on.
Without Redis, turn the switch off (or configure Redis) before upgrading, or their
routes answer 503. Routes whose required scopes or roles had spaces start
accepting the tokens they were meant to. See ADR 0046.

### `tls_binding` binds a session to the client certificate, and needs a secret

**Read this if you use the `tls_binding` middleware or the Settings switch "TLS
Session Binding".**

`tls_binding` refused every TLS request carrying the session cookie (nothing ever
issued the binding it checked) and did nothing over plain HTTP.

- It now binds the session cookie your backend sets to the client certificate of
  the TLS connection that received it: the gateway adds `<cookie_name>_binding`
  next to the session, and later requests must carry that session from the same
  certificate. Another certificate, no certificate, or plain HTTP is refused with
  `403`; a request without the session cookie is not checked. Signing out (the
  backend emptying or expiring the session) expires the binding too.
- It needs a `secret` of at least 32 characters, the same on every gateway serving
  the route. **A stored `tls_binding` without one no longer builds** and its routes
  answer `503`. It needs a TLS entrypoint that asks clients for a certificate.
- Saving a route that puts `tls_binding` on an HTTP entrypoint without TLS (or on
  no named entrypoint while one lacks TLS) is refused.
- The global Settings switch "TLS Session Binding" is retired: turning it on is
  refused, and one already on no longer does anything (it used to refuse every TLS
  request carrying the cookie) and logs a warning once. Use the middleware on the
  routes that need binding, and turn the switch off.

**Who is affected:** anyone with a `tls_binding` middleware (add a `secret` and serve
it on TLS with client certificates, or remove it) or with the global switch on
(turn it off; routes that were refusing every session start serving them).

### CORS: a blank origin list allows no origin, and `*` never carries credentials

- **A `cors` middleware with Allowed Origins left blank and no preset used to allow
  every origin; it now allows none.** Put `*` in the list for every origin, or name
  the origins. A blank field beside a preset still takes the preset's origins.
- The Permissive, Standard and gRPC-Web presets no longer turn credentials on.
  They granted `*` with `Access-Control-Allow-Credentials: true`, which every
  browser refuses, so credentialed cross-origin calls already failed; uncredentialed
  ones are unchanged.
- Saving credentials together with origin `*` (cors or grpcweb) is refused; a stored
  one is served without `Access-Control-Allow-Credentials`. Name the origins that
  send cookies or an `Authorization` header.
- A `grpcweb` middleware with the Restricted preset allowed every origin; it now
  allows none, as the preset says.

**Who is affected:** cors middlewares with an empty origin list (browsers calling
those routes cross-origin are now refused until you add origins or `*`), and
grpcweb middlewares on the Restricted preset.

### XFCC values are escaped, and Forward By forwards the gateway's URI

- Certificate fields in `X-Forwarded-Client-Cert` are now quoted and escaped when
  they contain `,` `;` `=` `"` `\` or a space, as Envoy's format requires; a
  certificate's URI SAN can no longer add pairs (such as a second `Hash=`). The
  subject is always quoted, now with XFCC escaping rather than Go's (its
  backslashes are no longer doubled). Backends parsing XFCC see the same values,
  correctly delimited.
- "Forward By" now emits `By=<by>` first, where `by` is a new field: the URI this
  gateway names itself (the URI SAN of its certificate, e.g.
  `spiffe://example.org/gateway`). Saving Forward By without an absolute URI is
  refused; a stored one emits no `By` and logs a warning, as before.

**Who is affected:** backends that read XFCC (values that needed quoting now
arrive quoted); xfcc middlewares with Forward By on (add `by`).

### Rate-limit Redis storage needs Redis; per-middleware "Trust Cloudflare Headers" is gone

- Saving a rate limit with `storage: redis` on a gateway with no Redis is refused.
  A stored one keeps limiting in each instance's memory (each instance allows the
  full limit) and logs `effective_storage=local`.
- The "Trust Cloudflare Headers" switch on rate-limit, IP-filter and GeoIP
  middlewares never changed the client address they saw: the entrypoint resolves
  it once, under Settings > Trust Cloudflare Headers (`waf.trust_cloudflare_headers`
  / `GATEON_TRUST_CLOUDFLARE_HEADERS`). The dashboard no longer shows it, and drops
  the stored key when you save. Saving a `trust_cloudflare_headers` value that
  disagrees with the global setting is refused, naming the global setting; one
  that agrees is accepted.

**Who is affected:** multi-instance deployments that chose Redis storage without
configuring Redis (configure Redis to share the count); anyone behind Cloudflare
who relied on the per-middleware switch (turn on the global setting -- it was the
only one that ever applied).

### A full disk no longer takes the gateway down, and the trace store has a size budget

The live trace store was bounded by age alone (about 1.1 KB a request, kept 7
days on `standard`), so traffic decided how much disk it used. On a full disk it
either retried a failed compaction in a loop at two cores, or -- when its
write-ahead log hit the full disk -- exited the whole process, proxy included.

- The trace store now has a **size budget**: 256 MiB / 2 GiB / 20 GiB on
  `minimal` / `standard` / `enterprise`, or `GATEON_TRACE_STORE_MAX_MB`. Past it the
  oldest traces are evicted every 30 seconds, whatever their age, down to four
  fifths of it (INFO line). An hour the trace archive has not copied yet is
  evicted anyway, with a WARN.
- **Below a free-space floor** on its disk (a twentieth of the disk, at least
  four memtables, at most 1 GiB) trace writes stop: each dropped trace is counted
  in `gateon_trace_dropped_total{reason="disk_full"}`, an ERROR line says so once a
  minute, and `/readyz` answers `200 ready, degraded: trace store paused: disk
  nearly full ...` until the free space is half as much again above the floor.
  Proxying is unaffected, so the instance stays in rotation; alert on
  `gateon_trace_dropped_total`.
- If the disk fills anyway, Pebble's retries back off (1 s doubling to 30 s), and
  a write that fails on the full disk stops the trace store for the life of the
  process (`/readyz`: `200 ready, degraded: trace store stopped ...`) instead of
  exiting it. Free the
  space and restart.
- Pebble's errors are logged at ERROR/WARN, rate-limited, instead of every one at
  INFO. New gauges: `gateon_trace_store_bytes`, `gateon_trace_store_max_bytes`.

**Who is affected:** every install with the trace store on (`standard`,
`enterprise`). On a busy gateway the budget, not the retention, now decides how
far back traces go -- 2 GiB is about 1.9 million requests, five hours at 100 req/s.
Raise `GATEON_TRACE_STORE_MAX_MB` or turn on the trace archive for more. A store
already over its budget is cut to it 30 seconds after the upgrade starts. A
Kubernetes readiness probe now takes a pod whose trace disk is nearly full out of
rotation. See ADR 0049.

### The gateway exits if the management port cannot bind, /readyz goes 503 for an unbound entrypoint and reports an unreachable database

- **The management listener failing to bind is fatal**: the process exits `1`
  with `refusing to run without a management plane: management listener could not
  bind <addr>`, and systemd's `Restart=on-failure` restarts it. It used to log
  `Management listen failed` and run on with no management plane.
- **An entrypoint that cannot bind** (its port held by another process) is still
  not fatal -- the other entrypoints keep serving -- but it is logged at ERROR,
  `/readyz` answers `503` naming it (`entrypoint websecure could not listen on
  :443: ...`), and `gateon_entrypoint_up{entrypoint="websecure"}` is `0`. It used to
  answer `200`.
- **The configuration database** is pinged every 10 seconds. While it does not
  answer, `/readyz` answers `200 ready, degraded: configuration database
  unreachable` -- the data plane keeps serving through it, so the instance stays
  in rotation -- `gateon_config_db_up` is `0`, and `POST /v1/login` answers `503` ("sign-in is
  unavailable ...") instead of `401` with the driver's error -- the dashboard shows
  "The gateway is not ready to sign you in yet" rather than "Invalid username or
  password".
- `/readyz` joins several reasons with `; ` (it used `, `).
- A 2FA sign-in against a database restored under a different session key now
  explains that, instead of answering `failed to decrypt secret: cipher: message
  authentication failed`.
- The startup line `Gateon API Gateway started` no longer carries a `port`; the
  management listener logs its own address.

**Who is affected:** anyone whose management port is taken at start (it now
restarts in a loop with the reason in the journal); anyone whose load balancer or
Kubernetes probe reads `/readyz`, which now also goes `503` for an unbound
entrypoint (a degraded instance -- full trace disk, unreachable configuration
database -- stays `200` and says so in the body); scripts that matched the
`401` of a failed sign-in during a database outage. See ADR 0049.

### A relative SQLite path is in the data directory, and a set-up gateway refuses to start without its database

- A relative SQLite path -- the default `gateon.db`, or any relative
  `sqlite_path`/`database_url` -- now resolves against `GATEON_DATA_DIR` (else
  `GATEON_STATE_DIR`, else `/var/lib/gateon` on Linux if it exists, else the
  working directory). It used to resolve against the working directory, so the
  tarball or a hand-run binary started elsewhere created an empty `gateon.db` and
  reopened first-run setup. The Pebble trace store moves with it.
- A gateway whose `global.json` says it was set up (`auth.enabled: true`, which
  setup writes) **refuses to start** when its SQLite database file is missing, or
  when the database it opens has no administrator, with a message saying how to
  restore it. It used to create an empty one and reopen setup to whoever reached
  the management port first.

**Who is affected:** the packaged systemd unit already started in
`/var/lib/gateon` and is unaffected. A tarball or hand-run install started from a
directory other than its data directory, with `GATEON_DATA_DIR` set elsewhere,
will now open the database in `GATEON_DATA_DIR`: move `gateon.db*` (and
`telemetry_pebble/`) there before upgrading, or set an absolute path. Anyone who
deliberately started a set-up gateway on an empty database to re-run setup must
now move `global.json` aside first. See ADR 0049.

### The access log is capped per second

The access log wrote one stdout line per request. Under journald's default rate
limit (10000 lines in 30 s) that silenced every line from the service -- ERRORs
and security events included -- once traffic passed about 333 req/s.

- At most 50 / 100 / 200 access-log lines a second (`minimal` / `standard` /
  `enterprise`) are written across the gateway; `GATEON_ACCESS_LOG_MAX_PER_SECOND`
  overrides it, `0` lifts the cap. A WARN once a minute says how many lines were
  left out. Below the cap nothing changes; the trace store still records every
  request.

**Who is affected:** deployments that ship the stdout access log somewhere and
serve more than the cap. Set `GATEON_ACCESS_LOG_MAX_PER_SECOND=0` (and raise
journald's `RateLimitBurst=` for the unit, or log to a collector that does not
rate-limit) to keep every line. See ADR 0049.

### Container image and Helm chart: global.json lives on the data volume, so first-run setup completes

The image had no `/etc/gateon`, and the chart mounted it read-only, so setup failed
(`read-only file system`) and so did every save of global settings.

- The image and chart now set `GLOBAL_CONFIG_FILE=/var/lib/gateon/global.json`
  (the chart: `<persistence.mountPath>/global.json`) and `GATEON_DATA_DIR`.
- A `global.json` mounted at `/etc/gateon/global.json` is a **seed**
  (`GATEON_GLOBAL_CONFIG_SEED`): copied to the data volume the first time the volume
  has none, and not read again.
- The image's `/var/lib/gateon` is owned by the nonroot user, so a named volume
  mounted there is writable: `docker run -v gateon-data:/var/lib/gateon -p 8080:8080
  <image>`. Still distroless, nonroot, CGO-free.
- The chart's `appVersion` is `1.0.0`, the release that exists (it was `2.7.0`);
  chart version `0.3.0`.

**Who is affected:** container users who mount a writable `/etc/gateon` and keep
`global.json` there: on the first start after the upgrade it is copied to
`/var/lib/gateon/global.json` (which must be on a persistent volume), and from then
on that copy is the live one. To keep the old layout, set
`GLOBAL_CONFIG_FILE=/etc/gateon/global.json` and `GATEON_GLOBAL_CONFIG_SEED=`.
Helm users: changes to `globalConfig`, `externalDatabase` or `redis` no longer
reach an existing install after its first start; change those in the dashboard.
See ADR 0049.

### First-run setup is all or nothing

A setup whose `global.json` write failed used to leave the administrator it had
created (and the auth service it had installed) behind; where `global.json` already
existed, that closed setup for good over a config without the session key or
`auth.enabled`. A failed setup now removes what it did, so setup stays open and a
retry starts clean.

**Who is affected:** nobody whose setup succeeded. See ADR 0049.

### The systemd unit holds only CAP_NET_BIND_SERVICE; eBPF and HA need a drop-in

- The packaged unit (and the one `gateon install` writes) no longer grants
  `CAP_BPF` and `CAP_NET_ADMIN`, which eBPF and HA's virtual IP need and nothing
  else does. Both features are off by default. To use either, link the shipped
  drop-in and restart:
  `mkdir -p /etc/systemd/system/gateon.service.d && ln -s /usr/share/gateon/systemd/ebpf-ha.conf /etc/systemd/system/gateon.service.d/ && systemctl daemon-reload && systemctl restart gateon`
  (with `gateon install`, `systemctl edit gateon` and paste the lines in
  doc/services.md).
- The unit adds systemd's standard sandboxing (`PrivateDevices`,
  `ProtectKernelTunables`/`Modules`/`Logs`, `ProtectControlGroups`, `ProtectClock`,
  `ProtectHostname`, `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`,
  `LockPersonality`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`,
  `SystemCallFilter=@system-service` with `SystemCallErrorNumber=EPERM`).
- `MemoryMax=90%`, and gateon now derives its Go soft limit from a cgroup memory
  limit when neither `GATEON_MEMORY_LIMIT` nor `GOMEMLIMIT` is set: 85% of it, about
  1.5 GiB on a 2 GB host -- the figure doc/deployment-sizing.md recommended. This
  also applies to a container started with `--memory` and no `GOMEMLIMIT`.
- `EnvironmentFile=-/etc/default/gateon`: put `GATEON_ENCRYPTION_KEY` there,
  `root:root 0600`, not in an `Environment=` line, which any local account can read
  with `systemctl show`.
- `Environment=GATEON_DATA_DIR=/var/lib/gateon`; `Documentation=` points at the
  right repository; the `# Environment=PORT=8080` hint is gone -- `PORT` never moved
  the management listener. Use `GATEON_MANAGEMENT_PORT`.

**Who is affected:** anyone running eBPF or HA under the packaged unit or `gateon
install`: after the upgrade, enabling either logs `eBPF is enabled but this process
lacks the capabilities` (HA: `Failed to add VIP`) until the drop-in is in place.
Anyone who ran something unusual from the gateway process (a hook needing a device
or a namespace) may need a drop-in relaxing the sandbox. On hosts with more than
2 GB, `MemoryMax=90%` and the derived soft limit apply in proportion. See ADR 0049.

### Package upgrades leave the service as you had it

The deb/rpm scripts enabled and restarted the service on every upgrade, undoing a
deliberate `systemctl disable` (a standby node, maintenance). On rpm it was worse:
the old package's scriptlet ran last and **stopped and disabled a running service
on every upgrade**.

- A fresh install still enables and starts the service. An upgrade records
  whether it was enabled and running first and leaves it that way, including when
  upgrading from v1.0.0 (whose own scriptlets still run).
- The Windows service wrapper XML is no longer installed as
  `/etc/gateon/gateon-service.xml`; an existing copy is left in place by dpkg as an
  obsolete conffile and can be deleted.

**Who is affected:** deb/rpm installs. rpm hosts that worked around the stop on
upgrade (re-enabling after each one) can stop doing so. See ADR 0049.

### Five wrong passwords no longer lock an account for everyone; sign-in failures are counted per address

A stranger sending five wrong passwords for `admin` used to lock the account for
fifteen minutes for everyone -- the owner's right password from their own address
included -- and could keep it locked indefinitely (M6).

- Failures are now counted per account **and source** (an IPv4 /24, an IPv6 /64):
  five lock that pair for fifteen minutes, and nobody else.
- Twenty failures for one account from any number of sources within fifteen minutes
  put it "under attack" for fifteen minutes (renewed while refused attempts keep
  coming). While it holds, only addresses the account has signed in from before may
  try; every other address gets "account locked". The eight most recent sign-in
  networks per account are remembered (migration 67, `users.login_sources`), so this
  survives a restart; an account that has never signed in since the upgrade has none
  yet.
- The counts are in memory and per instance: a restart clears them, and each node of
  an HA pair counts on its own.
- The stored count (`failed_attempts` / `locked_until`) is now used only by the
  two-factor code and by the password prompts inside the dashboard (password change,
  2FA setup). Wrong passwords there lock that prompt for fifteen minutes, not sign-in;
  wrong sign-in passwords no longer lock those prompts. A correct password no longer
  clears the two-factor code's count, which let whoever held the password guess TOTP
  codes without ever reaching the lock.
- Unknown usernames are answered exactly like real ones, including "account locked"
  and the time it takes (a bcrypt comparison).

**Who is affected:** everyone. Nothing to configure. If an administrator is refused
with "account locked" during an attack, sign in from a network the account has used
before, or wait fifteen minutes after the attack stops.

### New passwords must have at least 12 characters

There was no password rule: `a` was accepted, and an account could be created with
no password at all (M11).

- A password set at first-run setup, when creating a user, when an administrator
  resets one, or when you change your own must have at least 12 characters, at most
  72 bytes, must not contain the username, must not be one character repeated or a
  simple run, and must not be one of a short built-in list of the most common long
  passwords. The check is offline.
- Creating a user now requires a password. Editing a user without one keeps theirs.
- A refusal is `400` over REST (`InvalidArgument` over gRPC/Connect) naming the rule,
  and the dashboard states the rule under every password field.
- Existing passwords are not affected and keep working until they are changed.

**Who is affected:** anyone scripting user creation or password changes with short
passwords (`/v1/users`, `/v1/users/password`, `/v1/setup`). Development: the
`dev/seed` default password is now `gateon-dev-passphrase`; the e2e accounts use
`e2e-horse-battery-42`.

### An anonymous password change is refused even with authentication switched off

With no authenticated caller -- authentication switched off, or any path that
reached the API without a credential -- `POST /v1/users/password` and the gRPC
`ChangePassword` changed the password of whatever account id they were given (M3).
They now answer `403` / `PermissionDenied` and change nothing.

**Who is affected:** only a deployment that relied on changing passwords without
signing in, which is the hole this closes.

### New installs record a signed audit log, and the log can be verified

The audit log was off by default, so a default install recorded nothing, and its
HMAC chain was never checked (M8).

- **New installs:** first-run setup now turns `audit.enabled` and
  `audit.sign_entries` on and generates `audit.signature_key`.
- **Existing installs keep their setting.** `"enabled": false` is not written to
  `global.json` (it is the default), so an install that switched audit off cannot be
  told from one that never chose, and turning it on would override a deliberate
  choice. Instead the gateway logs at startup `the audit log is off ...`
  (`event=audit_disabled`) or `audit entries are not signed ...`
  (`event=audit_unsigned`). To turn it on: Settings, Audit, enable **and** sign.
- An administrator can verify the chain: **Audit Logs → Verify integrity** in the
  dashboard, or `GET /v1/audit/verify?from=<RFC3339>&to=<RFC3339>&limit=<n>` (gRPC/
  Connect `VerifyAuditChain`). Each call checks at most 5,000 entries (default 1,000)
  and answers `intact`, or the first entry that breaks the chain and why; continue
  with `afterId=<nextAfterId>`. With signing off it answers `400` (`FailedPrecondition` over gRPC/Connect) saying "audit signing is off".
- Entries written before signing was on, or while it was off, do not verify; start
  the check from a time after them.
- An unsigned entry now ends the chain and the next signed one starts a new one, as a
  restart already did.

**Who is affected:** new installs (audit on); existing installs with audit off (a
startup warning, no behaviour change); anyone with an HA pair writing one audit
database (each node chains on its own, so the combined log does not verify as one
chain).

### Prometheus can scrape `/metrics` with a long-lived, revocable API token

`/metrics` accepted only a user's eight-hour session, so a scraper needed a viewer
account and a script signing it in on a timer.

- An administrator creates a token under **API Tokens** in the dashboard (or
  `POST /v1/api-tokens {"name":"prometheus","scopes":["metrics:read"],"ttlDays":0}`,
  gRPC/Connect `CreateApiToken`). The token (`gateon_tok_…`) is shown **once**; only
  its hash is stored. Tokens are listed with a hint, creator, last use and expiry,
  and revoked with `DELETE /v1/api-tokens/{id}` (`RevokeApiToken`), effective on the
  next request. At most 50 exist. Administrators only.
- The token is accepted only as `Authorization: Bearer <token>` on `/metrics`. On
  any other path, and on every transport, it is refused with `401`; it is never a
  dashboard session, and the proxy strips anything shaped like one before a request
  reaches a backend.

**Who is affected:** anyone scraping `/metrics`. The viewer-account workaround keeps
working; replace it at your convenience: create a token, put it in a file only
Prometheus can read, and point the job's `authorization.credentials_file` at it
([production-runbook.md](production-runbook.md) section 5 has the steps).

If you used the viewer account for scraping: after switching, delete that account
and its timer (`/usr/local/bin/gateon-metrics-token`, `/etc/gateon-metrics.pw`).

### IP reputation feeds now refuse what they list, on every route (ADR 0044)

"IP Reputation -- sync with threat feeds to block known malicious actors"
(Settings > Advanced Security) used to load the feeds and refuse no one unless
the route also ran a WAF with its own, separate "IP Reputation" switch on. A
listed address is now refused on every HTTP and TCP entrypoint and every route,
with or without a WAF, by the same check that refuses a blocked address: HTTP
answers `403 Forbidden: Address Listed by an IP Reputation Feed`, a TCP
entrypoint closes the connection, and the Security Hub lists the refusal.
Loopback and `GATEON_MITIGATION_ALLOWLIST` are never refused. A feed listing
scores 100, so any block threshold up to 100 refuses it; set the threshold
above 100 to load a feed without refusing anyone.

The WAF's own "IP Reputation" switch is now labelled "Behavioural Reputation":
it refuses clients whose reputation on this gateway has fallen below 20, as it
did before.

**Who is affected:** installs with IP reputation enabled and feed URLs set.
Before upgrading, check what your feeds list -- in particular any private or
internal range a broad feed may include -- and add addresses you must keep
serving to `GATEON_MITIGATION_ALLOWLIST`.

### A country list needs a GeoIP database, and the GeoIP card says what the lists do (ADR 0044)

Without a MaxMind database every client resolves to the unknown country `XX`,
so a global "Blocked Countries" list refused no one -- on a default install,
which has no licence key and so no database -- while saving with success, and
an "Allowed Countries" list refused everyone. Now:

- Saving a new or changed country list (Settings > GeoIP, `PUT /v1/global`,
  gRPC, or a "block country" recommendation) with geofencing enabled and no
  database is refused with `400`/`InvalidArgument`, saying what to install:
  upload a GeoLite2 City or Country `.mmdb` under Settings > GeoIP, download it
  there with a MaxMind licence key, or set `geoip.db_path` /
  `GATEON_GEOIP_DB_PATH`. Naming a database that opens in the same save is
  enough. An entry that is not a two-letter country code (`USA`, `China`) is
  refused, globally and on a route `geoip` middleware, where it used to match
  nothing.
- A list already stored keeps saving with your other settings. While no
  database is loaded, an allow list refuses every request (fail closed, as
  before) and a block list refuses no one (as before); both are now logged at
  error once a minute, and the GeoIP card shows a red notice saying which, from
  the new `geofence` field of `GET /v1/geoip/status`.
- Saving a GeoIP database path that does not open no longer unloads the
  database already in use (it used to, until restart). A GeoLite2 Country
  database on its own now resolves countries.

**Who is affected:** installs with a global country list and no GeoIP database
(their block list was not enforced; install a database to enforce it), and
API clients that save country names instead of codes.

### A route WAF keeps what the global WAF runs, and its category switches work (ADR 0044)

With the global WAF on, a route that has its own `waf` middleware runs that WAF
instead of the global one. It used to fill the settings it left unset from the
raw global switches, which the global WAF itself ignores, so attaching a WAF to
a route dropped the global WAF's malware and ransomware rules there (`/c99.php`
went from 403 to 200), its paranoia level, and its enforcement mode. A route
WAF now starts from what the global WAF actually runs; a setting the route
sets explicitly adds to or narrows it on that route only.

The category switches on a route WAF (SQL Injection, XSS, File Inclusion, Code
Execution, PHP, Java, Node.js, Scanner) now switch their family off, including
the gwaf core rules that blocked it whatever the switch said. Turning Code
Execution off also lets PHP, Java and Node.js code injection through. Rules no
switch names still run.

The global WAF card shows what the global WAF runs, read from the running
engine, instead of switches it never read: every category is on and cannot be
narrowed gateway-wide; narrow a family for one application with a route WAF.
"Use OWASP Core Rule Set" and "DOS Protection" are gone (neither selected any
rule; a stored `dos_protection` is named in the log). The card and the route
editor read the new `GET /v1/waf/effective`, and the security posture's `waf`
carries `mode` (`enforcing`, `audit_only`, `off`), so an audit-only WAF is no
longer reported the same as an enforcing one.

A route WAF no longer has its own "Trust Cloudflare Headers" switch. The client
address is resolved once, from Settings > Global WAF Settings > "Trust
Cloudflare IPs/Headers" (or `GATEON_TRUST_CLOUDFLARE_HEADERS`), which only an
administrator may change. A route `waf` middleware whose
`trust_cloudflare_headers` disagrees with that setting is refused at save, and
a stored one fails to build, so its route answers 503 until the key is removed
or made to match; one that agrees keeps working. The same holds after an
administrator changes the global setting.

**Who is affected:** routes with their own `waf` middleware under an enabled
global WAF -- they now enforce malware and ransomware detection and the global
paranoia level and mode, so review them for false positives before upgrading;
set `malware_detection`, `paranoia_level` or `audit_only` on the route to keep
the old behaviour deliberately. Route WAFs with a category switched off now
stop detecting that family.

### A malformed IP filter entry is refused, and a stored one takes its route down until fixed (ADR 0047)

**Read this before upgrading if any `ipfilter` middleware has an entry that is not
a plain IP address or CIDR** -- a wildcard (`10.0.0.*`), a range
(`10.0.0.1-10.0.0.9`), a mask past the address size (`/33`, `/129`), or two
addresses typed as one entry (`10.0.0.1 10.0.0.2`).

Such an entry used to be dropped with a server-side WARN while the save answered
`200`: a deny list of `127.0.0.*` blocked nobody, and the operator was told it was
saved.

- Saving one is now refused (REST `400`, gRPC error, config import error), naming
  the list and the entry: `middleware config "deny_list": "127.0.0.*" is not
  valid: ...`. The dashboard marks it before you save.
- **An existing filter with such an entry no longer builds after the upgrade, and
  every route using it answers `503`** until the entry is fixed, as any security
  middleware that cannot be built does. It is not served unfiltered.
- Fix: write the CIDR (`10.0.0.0/24` for `10.0.0.*`), or split the entry.

**Who is affected:** operators with a hand-typed `allow_list`/`deny_list`. Lists
the dashboard's Cloudflare import or "Block IP" wrote are well-formed.

### Every service's targets are health-checked, and an all-down route answers 503 (ADR 0047)

A service with health check "Auto" and no path -- the dashboard's default -- ran
no health check at all: a dead backend stayed in rotation for good (one request in
N got `502`) and the dashboard showed it healthy and CLOSED.

- With no path, the gateway now checks each target by **opening a TCP connection
  to it** every 15 s. Two failures in a row take it out of rotation; two successes
  bring it back (the existing Unhealthy/Healthy Threshold settings). A path, when
  set, is requested as before (a 5xx or no answer is a failure).
- When every target is out of rotation the route answers **`503`** "no healthy
  targets available for service" (it answered `502`).
- Saving a service with health check type **HTTP and no path is refused**
  ("an HTTP health check needs a path"); choose Auto or TCP to check by
  connecting. A stored one checks by connecting.
- Negative health thresholds are refused at save.

**Who is affected:** every HTTP/gRPC service without a health check path (they
now get checked; backends will see a TCP connection every 15 s), and monitoring
that alerts on `502` for a service with no live backend (it is `503` now).

### Target weights are honoured under Round Robin, and refused where they would be ignored (ADR 0047)

The service form showed a Weight on every target, and the default policy, Round
Robin, ignored it (weights 1:2:6 gave 30/30/30).

- **Round Robin now sends each target traffic in proportion to its weight**,
  interleaved (6:1:1 goes a a b a a c a a, not six in a row). Equal weights --
  what the form saves unless you change one -- are plain rotation, as before.
  Weighted Round Robin is the same balancer, and is now interleaved too.
- Once any target has a weight, a target at weight 0 gets no traffic (standby), as
  under Weighted Round Robin. A service saved through the API with some targets at
  0 and others above 0 under Round Robin will stop sending traffic to the 0s.
- Least Connections, the predictive balancer, and every TCP/UDP service ignore
  weights, so **saving one of them with different weights on its targets is
  refused**; the form hides the weight field there and saves 1. Unknown policy
  names (`ip_hash`, typos) and negative weights are refused too -- they were
  saved and balanced round robin.
- A canary can now run on a Round Robin service.
- REST answers a refused service save `400` with the reason (every save error was
  `500 "failed to save service"`); gRPC answers `InvalidArgument`.

**Who is affected:** services whose targets have different weights under Round
Robin (traffic shifts to match the weights on upgrade); API/config users with
non-standard policy names or weights on least-connections/TCP services (their next
save is refused; stored services keep running).

### "Max Concurrent Requests" says it is per client address; its total mode is a total (ADR 0047)

The in-flight middleware always counted per client address (`429` when one address
is at the cap); the dashboard labelled it "Max Concurrent Requests". It now reads
"Max Concurrent Requests per Client Address", and the editor offers the other mode,
"In total, for each route this is attached to" (`per_ip: "false"`, `503` when
full). That mode used to count per request `Host` -- which the client writes -- so
it capped nothing; it is now one count per route.

**Who is affected:** anyone who set `per_ip: "false"` in raw JSON (the cap now
holds), and anyone who read the old label as a total (it never was; choose the
total mode if that is what you want).

### Circuit breakers can be created in the dashboard, and an open one shows OPEN (ADR 0047)

Middlewares > Add Middleware > Circuit Breaker (error threshold, minimum requests,
window, sleep window). On the Circuit Breaker page and in route stats, a target
behind an open breaker now reads OPEN (it read CLOSED while the route answered
`503`), and `/v1/routes/stats` carries `breaker` with the route breaker's own state.

**Who is affected:** dashboards and scripts reading `circuitState` -- it is OPEN
when either the health check or the route's breaker has taken the target out.

### Dashboard counts survive configuration changes and memory-pressure purges (ADR 0047)

Per-target request and error counts started again at zero whenever a route was
rebuilt -- on any service save (even of another service) and when the resource
governor purged caches above 80% host memory. They now carry over for every
target the rebuilt route keeps.

**Who is affected:** nobody needs to act.

### Mitigating a loopback or allowlisted address says it is not enforced (ADR 0047)

`POST /v1/diagnostics/mitigate` for `127.0.0.1`, `::1` or an address in
`GATEON_MITIGATION_ALLOWLIST` answered "successfully mitigated" while every request
from it was still served. The block is still recorded, but the answer is now
`success: false`: "recorded on the block list but is not enforced", naming the
exemption.

**Who is affected:** scripts that treat that success as "blocked" (it never was).

### Canary rollback judges each step on its own traffic, and is shown on the Circuit Breaker page (ADR 0047)

A canary's error-rate limit was compared with the service's lifetime error rate, so
a long healthy history diluted a failing step below any limit. Each step is now
judged on the requests it served. A rollback is listed in the Circuit Breaker
page's Event Timeline as `service <id> (canary)`, OPEN, with the step's rate.
The p99 limit still reads the service's lifetime latency.

**Who is affected:** canaries with an error-rate limit roll back sooner, on the
step that fails.

### The JavaScript challenge works on every route, and only a client that does its work passes

**Read this before upgrading if any route uses a `bot_management` middleware with
`enable_js_challenge`, or if global proof-of-work (`security_advanced.pow`) is on.**

The bot-management JavaScript challenge did not do what it was described as doing
(ADR 0045):

- **On a route with a path rule it could never be passed.** The challenge page
  fetched `/_gateon/seed` and posted to `/_gateon/challenge`; on a route such as
  `PathPrefix(/app)` those requests are not the route's, so they were `404` and
  every visitor was held at the challenge. Only routes whose rule happened to
  match `/_gateon/*` (a `Host()` route, a catch-all) worked.
- **Where it worked, curl passed it.** The "work" was a two-second wait: fetch the
  seed, sleep, post it back. No JavaScript had to run.

Now:

- The page asks the browser to find a proof of work (an 18-bit SHA-256 puzzle;
  0.1-0.5 s on a desktop browser, a second or two on a slow phone) and hands the
  answer back **at the URL that was challenged**, marked by the
  `X-Gateon-Challenge` header. That reaches the same route whatever its rule.
  The gateway answers those marked requests itself; they never reach the backend.
  `/_gateon/seed` and `/_gateon/challenge` are no longer special paths.
- A pass (`gateon_bot_challenge` cookie, HttpOnly, bound to the client's address
  and User-Agent, lasting `challenge_timeout`) is issued only for a correct answer.
  **Every pass issued before the upgrade is invalid, so every visitor is challenged
  once more after it.**
- **Clients that cannot run JavaScript are refused on a challenged route** --
  curl, SDKs, most uptime monitors and link-preview bots. That was always the
  intent; it is now true. Give such clients a route without the middleware: the
  challenge has no allowlist (`GATEON_MITIGATION_ALLOWLIST` exempts a source from
  proof-of-work, not from this).
- The challenge proves work, not a human: a headless browser passes, and so does a
  bot that solves the puzzle natively, at a CPU cost per address and User-Agent.
  The dashboard now says so beside the switch.
- The page is accessible: a status line read by screen readers, a `<noscript>`
  explanation, and, when a check fails or expires, a message and a Try again
  button instead of an automatic reload.

**Who is affected:** every route with a `bot_management` middleware that has the
JavaScript challenge on (or inherits it from the global Bot Management defaults).
Routes with a path rule start admitting browsers for the first time; all such
routes start refusing clients that run no JavaScript.

### "Browser Integrity" is relabelled "Browser Header Check", and now checks Firefox

The check never verified that a client was a browser: it refuses a request with no
User-Agent, and one whose User-Agent claims a modern browser but carries none of
the `Sec-Fetch-*` headers such a browser sends. A client that does not claim to be
a browser (curl, python-requests, Googlebot) passes, as before. The dashboard now
says exactly that. **Firefox is now among the browsers it checks** (Firefox has
sent fetch metadata since version 90): a request claiming Firefox without any
`Sec-Fetch-*` header is now refused with `403`.

**Who is affected:** routes with `enable_browser_integrity`; scripts that send a
copied Firefox User-Agent and nothing else.

### Proof-of-work now challenges the clients its setting names

Global proof-of-work (`security_advanced.pow.score_threshold`, "Serve challenge when
IP threat score exceeds this", recommended 5) challenged a client only when its
*reputation* was below the threshold. At 5 that is a reputation the reputation
blocker refuses first, so **proof-of-work has never challenged anyone**. It now
challenges a client whose threat score, `100 - reputation`, *exceeds* the
threshold -- the scale the tarpit beside it already used. At the recommended 5 a
client is challenged after its first penalty (one blocked attack takes a score
from 100 to 50).

- A threshold of `0` challenges every client with any penalty, not every client.
- A route-level `pow` middleware's `threshold` (default `20`) has the same meaning
  now: it challenges a client whose threat score exceeds 20.
- A browser that solves the puzzle gets a `gateon_pow_pass` cookie for 10 minutes,
  bound to its address and User-Agent; before, the solution was honoured only on
  the request that carried it, so the browser page solved, reloaded and was
  challenged again, indefinitely. API clients may still send the solution headers
  on each request.
- Serving a challenge is no longer recorded as a security threat. It used to be,
  and a challenge plus the blocked attack that caused it correlated into a
  critical incident that dropped the client's reputation to 0, so it was blocked
  before it could solve anything. Served and solved challenges are counted on
  `gateon_middleware_bot_management_total{outcome="pow_challenge_served"|"pow_challenge_solved"}`.
  A wrong solution is still recorded as a threat.

**Who is affected:** anyone with `security_advanced.pow.enabled` or a `pow`
middleware. Expect challenges (`429` with the puzzle for API clients, the challenge
page for browsers) where there were none. If that is not wanted, raise the
threshold or turn proof-of-work off before upgrading.

### The global Bot Management settings are labelled as route defaults

The Settings > WAF "Global Bot Management" switches were never applied to every
route: they are the defaults a route's Bot Management middleware falls back to for
any setting the route leaves unset. The section is now titled "Bot Management
Defaults" and says so. Nothing about their effect changed.

**Who is affected:** operators who turned these on expecting every route to be
protected; attach a Bot Management middleware to the routes that need it.

### The Security Hub's numbers are computed from what the gateway runs (ADR 0048)

Several Security Hub figures were constants or counted the wrong thing. They now
describe the running gateway, and most installs will see them change on upgrade.

- **Security Posture %** is computed by the gateway from configuration only: a
  weighted sum of WAF (40), TLS on reachable entrypoints (20), management plane
  not exposed (20), anomaly detection (10) and audit logging (10). A control
  earns full weight when it blocks, half when it only detects (an audit-only
  WAF) or covers part, none when off. Traffic and attackers no longer move it.
  It used to read 100% with nothing configured; expect a lower figure. Hover
  it for each control's share.
- **WAF card** reads "Detecting only (audit)" for an audit-only WAF and
  "Blocking on N of M routes" when some route's own WAF middleware is audit-only
  or it has none. A route WAF replaces the global one on that route, so a
  route-level audit-only WAF is now shown as such. The AI Advisory reports
  audit-only as a finding.
- **Signature engine card** reads "Not running" unless a route has a File
  Security middleware with signature scanning; it used to say "11 rules active"
  on every install.
- **Client Reputation card** (was "Reputation Status: Good", a constant) counts
  the clients whose reputation has been lowered and gives the lowest score.
- **Mitigation funnel** counts each request once (it showed twice the traffic)
  and no longer lists IP- or host-filter refusals as "Allowed": "Allowed" now
  means a backend was reached, refusals no stage claims appear as "Other
  refusals", blocked sources (shuns, fingerprint blocks) are their own stage.
  The counts restart with the gateway, as before.
- **Threats from 127.0.0.1 / ::1 are now recorded and shown.** Behind a local
  nginx or cloudflared without trusted proxies every client is loopback, and
  their WAF blocks used to be invisible. They are held against nobody: no
  reputation penalty, no automatic block, no correlated incident.
- **Attack-trend chart** now has data on SQLite (it was always empty), and on
  Postgres its hours are no longer shifted by the server's UTC offset.
- **Bandwidth by IP** counts a chunked upload at its size (it counted 256 bytes).
- **"Unlisted route" findings** are no longer raised for requests refused before
  routing (a banned client hitting routes that exist).
- **Bot management coverage** in the AI Advisory counts the routes that carry a
  bot management middleware; the global bot settings are only its defaults and
  no longer count as protection. The funnel's bot stage now counts challenges
  served and bot blocks (it counted outcomes nothing records).
- **"Mitigated in 24h"** is relabelled "Mitigated Today": it has always counted
  since midnight.

**API:** `GET /v1/security/posture` adds `waf.mode`, `waf.routes`,
`signatures.routes` and `score`, and **removes `waf.autoUpdate`**: rules are
compiled in and nothing downloads them. `waf.customRulesFromDisk` reports what
the old `auto_update_rules` flag does (load a rules directory already on disk).
Keys are lowerCamel, as they always were on the wire; doc/security-posture.md
now says so. The metrics snapshot's `mitigationFunnel` adds `refused`,
`answered`, `otherRefused` and `mitigationBlocked`; `totalMitigated` now equals
`refused`. New Prometheus counter: `gateon_request_outcomes_total{outcome}`.

**Who is affected:** everyone who reads the Security Hub, and anyone whose SIEM
or script reads `waf.autoUpdate` (gone) or derived "allowed" traffic from the
funnel (now counted once).

### The compress middleware honours "Max Compressed Size" (max_buffer_bytes)

The setting was saved and never read, so every response was compressed. A
response that declares a longer body (Content-Length) is now sent uncompressed;
the default is 10 MB. **Who is affected:** routes with a compress middleware
whose responses declare more than the configured size -- they now go out
uncompressed, as the setting always said.

### make check-config checks that a setting is used, not just mentioned

`go run ./scripts/checkconfig` (also in `make sec` and CI) now fails when a
struct field filled from configuration is read by nothing, and when a key the
dashboard's middleware editors write has no row in the effect registry
(`internal/middleware/dashboard_key_effects_test.go`) and no line in
`scripts/checkconfig/effects-baseline.txt`. **Who is affected:** contributors
adding a dashboard setting -- add an effect row that flips it and shows the
gateway answering differently.

### OIDC and JWKS-verified JWT auth now require an audience; existing ones without one stop serving

**Read this before upgrading if any `auth` middleware is `type: oidc`, or `type: jwt`
with a `jwks_url`.**

An identity provider's published keys sign the tokens of every application it
serves. With the audience left blank (the dashboard labelled it "Audience
(optional)"), these middlewares accepted a token the provider issued to *any other
application* -- for a public provider such as Google, any application at all.

- Saving an `oidc` auth middleware, or a `jwt` one with `jwks_url`, without
  `audience` is now refused (REST `400`, gRPC error, config import error) with:
  "an audience is required: an identity provider's published keys sign tokens for
  every application it serves, so without one this route accepts a token issued to
  any of them; set audience to this API's identifier at the provider, or set
  allow_any_audience=true if the provider issues tokens to this gateway alone".
- **An existing middleware without an audience fails closed after the upgrade:** it
  no longer builds, and every route using it answers `503` until it is fixed, as any
  security middleware that cannot be built does. Nothing is silently accepted.
- Fix: set `audience` to the value your API's tokens carry in `aud` (the API
  identifier at Auth0/Okta/Keycloak, the client ID for Google ID tokens). A token
  whose `aud` does not include it is refused with `401`.
- If the provider issues tokens to this gateway alone and they carry no useful
  `aud`, set the named opt-out `allow_any_audience: "true"` (the dashboard's red
  "Accept a token issued for any audience" switch). A blank audience is never read
  as that choice.
- A `jwt` middleware verified with a shared `secret` (HS256) is not affected; the
  audience stays optional there.

**Who is affected:** every `oidc` auth middleware, and every `jwt` one with
`jwks_url`, saved without an audience. Before upgrading, list them
(`GET /v1/middlewares`, or the Middlewares page) and add an audience, or plan for
their routes to answer 503 until you do. The `oidc` login middleware (type `oidc`,
not `auth`) already checks its `client_id` and is not affected. See ADR 0043.

### A basic-auth user with no password is refused, and no longer lets anyone in

A basic-auth `users` entry with an empty password -- `alice:pw,user2:`, which is
exactly what the dashboard's "Add user" row saved when the password was left
blank -- authenticated anyone who sent that user name and no password.

- Saving such a list is refused with `basic auth users: user "user2" has no
  password; ...` (a user with no name is refused too). The dashboard flags the row
  and keeps Save disabled until a password is entered; users whose passwords are
  already stored keep them, as before.
- A stored list with such a user no longer builds: routes using it answer `503`
  until the user is given a password or removed.
- A request with an empty user name or password is never accepted.
- The parse errors for this list no longer quote the entry they refuse (it may be
  a password typed without its name).

**Who is affected:** basic-auth middlewares with a passwordless user. They were
open under that name; after the upgrade their routes refuse until fixed.

### A route rule that does not parse is refused instead of matching every request

A rule the router could not read in full -- an unclosed quote or parenthesis,
`Hots(...)` for `Host(...)`, `PathPrefx(...)`, a regex that does not compile, an
empty value such as `Host(``)` -- used to be saved with `200` and matched **every**
request on its entrypoints, taking traffic (and skipping the auth and WAF) of the
routes that described it.

- Saving such a rule is refused: REST `400`, gRPC `InvalidArgument`, config import
  and `/v1/config/validate` list it as an error. The message names the character
  and the reason, for example `invalid route rule at character 1: unknown condition
  "Hots" (did you mean Host?)` or `invalid route rule at character 28: expected )
  to close Host(, but the rule ends here`.
- A rule already stored that does not parse **matches no request** (it no longer
  matches every request) and is logged once:
  `route rule does not parse; every route with this rule matches no request until
  it is fixed`. Requests it used to capture now reach the route they describe, or
  404.
- The rule is now read in full, which changes the meaning of rules the old reader
  got wrong: a leading `!` negates only the condition it precedes
  (`!Path(`/a`) && Host(`x`)` used to mean "not (path /a and host x)"); a second
  condition of the same kind is honoured (`PathPrefix(`/api`) &&
  !PathPrefix(`/api/admin`)` now excludes admin); parentheses group; `Host` takes
  exactly one value (write `Host(`a`) || Host(`b`)`); `Methods` takes one method
  per value (`Methods(`GET`, `POST`)`); values are literal, with no backslash
  escapes.
- TCP/UDP routes may still have no rule, and the dashboard's `L4()` is accepted.
- The dashboard's rule builder no longer doubles backslashes in values (it did so
  on every save, which broke `PathRegex` patterns).

**Who is affected:** anyone with a mistyped rule (check the log for the line above
after upgrading), and API clients or imports that write such rules. Rules written
by the dashboard's builder, the Kubernetes controller and the unlisted-route
detector all parse. See ADR 0043.

### Block lookups no longer remember a database error as "not blocked"

When the database could not answer whether an address (or a client fingerprint) was
blocked -- a Postgres restart or failover, an exhausted pool, SQLite busy past its
timeout -- the answer "not blocked" was cached with no expiry, so a blocked address
was served during the error **and after the database recovered**, until the cache
entry happened to be evicted.

- A failed lookup is never cached; the next lookup after recovery enforces the
  block. Errors are counted in the new metric
  `gateon_mitigation_lookup_errors_total{kind="ip"|"user"}` and logged at most once
  a minute ("block lookup failed; deciding requests from the cache until the
  database answers").
- During a database outage, requests are still served (fail open), except from
  addresses or fingerprints this node already holds a block for, which stay
  refused. Refusing everything the cache cannot vouch for would turn a database
  outage into a full outage.
- A "not blocked" answer is now re-read after one to two minutes, so a block made
  on another node (or written straight to the database) is enforced within that
  time; it used to wait for cache eviction.
- A fingerprint an operator released and then blocked again is blocked; the
  release used to outlive the new block on the node that made it.

**Who is affected:** nobody needs to change anything. Multi-node installs will see
blocks made on other nodes take effect within two minutes, and a little more
database read traffic from the re-reads (one indexed read per active client per
one to two minutes). Alert on `gateon_mitigation_lookup_errors_total` if you want
to know when the block list was decided without the database. See ADR 0043.

### A request no longer turns off its own timeouts; WebSockets and event streams get an idle timeout and a maximum lifetime

Every request on an HTTP entrypoint now gets the entrypoint's read and write
deadlines (`read_timeout_ms` / `write_timeout_ms`, 15 s by default), whatever
headers it carries. Any `Upgrade` header, or an `Accept` naming
`text/event-stream`, used to remove both, on any route -- so a client could hold
a connection open indefinitely with a slow body or a slow read by adding one
header. A response is now lifted off the deadlines only when the server made it
a stream:

- a **WebSocket** once its backend has answered `101`. Until then the upgrade is
  an ordinary request, and the backend has the HTTP transport's 1-minute
  response-header timeout to answer it;
- an **event stream** once the server has answered `200` with
  `Content-Type: text/event-stream` -- whether or not the client sent
  `Accept: text/event-stream`. A real event stream fetched without that header
  used to be cut at the write deadline; it no longer is.

A lifted stream is then bounded by two new values instead of none:

| | minimal | standard | enterprise | environment variable |
| :--- | :--- | :--- | :--- | :--- |
| Idle timeout (nothing moved in either direction) | 2 min | 5 min | 10 min | `GATEON_STREAM_IDLE_TIMEOUT` |
| Maximum lifetime | 1 h | 4 h | 12 h | `GATEON_STREAM_MAX_LIFETIME` |

Both take a Go duration (`90s`, `30m`, `24h`); `0` disables that bound. A byte in
either direction keeps a WebSocket open, so a server pushing to a quiet client is
not idle.

HTTP/3 requests now get the entrypoint's deadlines too. They had none.

**Who is affected:** WebSocket applications that stay silent for longer than the
idle timeout without pinging, or that expect one socket to live longer than the
maximum lifetime -- they are closed and must reconnect (browser `EventSource`
reconnects on its own); raise or disable the bound with the variables above.
Clients that sent `Upgrade` or `Accept: text/event-stream` on ordinary requests
-- long uploads, slow downloads -- now get the entrypoint's timeouts like any
other request; raise `read_timeout_ms` / `write_timeout_ms` on the entrypoint if
they need longer. See ADR 0042.

### Request headers are capped at 32 KiB (64 KiB on enterprise) and refused with 431 past it

Every HTTP listener -- each entrypoint over HTTP/1, HTTP/2 and HTTP/3, and the
management listener -- used to buffer up to 1 MiB of request header per
connection. A connection still sending its header is held before any request
limit sees it, so 1000 of them (the minimal profile's connection cap) could hold
more than a 2 GB host has. The cap is now the profile's `MaxHeaderBytes`:
**32 KiB** on minimal and standard, **64 KiB** on enterprise. A request whose
header is larger is answered **`431 Request Header Fields Too Large`** (over
HTTP/2, a header list far past the cap closes the connection instead).
`GATEON_MAX_HEADER_BYTES` (bytes, a positive integer) overrides it for every
listener.

**Who is affected:** clients that send very large headers -- many or large
cookies, long bearer tokens or JWTs in headers. If they start getting 431, set
`GATEON_MAX_HEADER_BYTES` (for example `65536`); the arithmetic for what each
profile can afford is in ADR 0042.

### The management listener bounds every request and caps connections per address

One address holding slow request bodies to an unauthenticated endpoint
(`/v1/auth/2fa/verify`) could make the whole management port -- `/healthz`
included -- answer 503 for as long as it liked. The management listener now has:

- **Per-request timeouts.** A request body has 30 s to start arriving and must
  then keep up at least 32 KiB/s (a GeoIP database upload over a slow link still
  finishes; a body sent a byte at a time is cut at 30 s). Once the request is in,
  the handler has 5 minutes to answer. The dashboard's event streams are not
  bound by these; they get the stream idle timeout and lifetime above, and
  reconnect on their own.
- **A per-source-address connection cap**, the same one the entrypoints have
  (`GATEON_ENTRYPOINT_MAX_CONN_PER_ADDR`, default 128 / 256 / 1024 by profile;
  `0` disables it). Loopback and `GATEON_MITIGATION_ALLOWLIST` are exempt, so an
  operator on the host is never locked out.
- **A 64 KiB body cap on the endpoints served before sign-in**: `/v1/login`,
  `/v1/setup`, `/v1/setup/test-db`, `/v1/auth/2fa/enroll`,
  `/v1/auth/2fa/verify` (and the gRPC Login and Setup methods). A larger body is
  refused with 413. Authenticated endpoints keep their existing limits.

**Who is affected:** many dashboard users or scripts behind one NAT address
holding more than the per-address cap of management connections at once -- add
the address to `GATEON_MITIGATION_ALLOWLIST` or raise the cap. Management
requests that took longer than 5 minutes to answer once received are now cut.
See ADR 0042.

### Proxied apps no longer receive the dashboard session

The proxy used to forward the `gateon_session` cookie to backends. Browsers do
not scope cookies by port, so with the dashboard on `host:8080` and apps on
`host`, every app received the administrator's eight-hour session. The proxy now
removes the session cookie (under either of its names) from every request it
forwards, on HTTP/1, HTTP/2, gRPC and WebSocket alike, and leaves every other
cookie as the client sent it. A `Bearer` token the management plane accepts is
withheld from backends too; an application's own tokens, PASETO ones included,
pass as before.

**Who is affected:** nobody who was not relying on a backend seeing the
dashboard's credential, which no backend should. Route middlewares still see the
request as the client sent it. See ADR 0041.

### The session cookie is `__Host-gateon_session` over TLS, and SameSite=Strict

Over TLS (directly, or behind a trusted proxy that sets `X-Forwarded-Proto:
https`) the session cookie is now named `__Host-gateon_session`, which a sibling
subdomain or a plaintext response on the same host cannot set or overwrite. On
plain HTTP it keeps the name `gateon_session`, because browsers refuse the prefix
without `Secure`. The cookie is now `SameSite=Strict` instead of `Lax`; the
dashboard is a single-page app whose API calls are all same-origin, so following
a link into it still lands signed in.

Sessions signed in before the upgrade keep working: the old name is still
accepted on TLS for this release, and the next sign-in or sign-out over TLS
expires it. **The old name will stop being read over TLS in the release after
this one**; anyone still signed in under it then signs in again.

**Who is affected:** dashboard users over TLS (nothing to do; sessions survive).
Tooling that reads the cookie by name over TLS must read
`__Host-gateon_session`; API clients should use `Authorization: Bearer`, which
is unchanged.

### The management API refuses writes another page asked for

Every state-changing management request -- `POST`, `PUT`, `PATCH`, `DELETE`,
REST and Connect, sign-in and setup included -- and the `/v1/logs` WebSocket
handshake are now refused with `403` when the browser reports that another page
made them: `Sec-Fetch-Site: same-site` or `cross-site`, or (from an older
browser) an `Origin` whose host is not the one the request was sent to. Before
this, a page on any other port of the dashboard's address, or on a sibling
subdomain, could change the configuration with an administrator's cookie --
including granting its own origin credentialed CORS access.

REST writes under `/v1/` must also send their body as `application/json`
(Connect and gRPC types are accepted; `multipart/form-data` only on
`/v1/certs/upload` and `/v1/geoip/upload`). A write with a body that is
`text/plain`, a form, or has no `Content-Type` gets `415`. A write without a
body needs no type.

**Who is affected:**
- Scripts and API clients are unaffected if they send no `Origin` and no
  `Sec-Fetch-Site` header -- curl, Python `requests`, Go's `net/http` and
  Prometheus send neither -- and send JSON. A script that posts a JSON body
  without `Content-Type: application/json` (curl's `-d` alone sends
  `application/x-www-form-urlencoded`) now gets `415`: add the header.
- Scripts driven through a browser or a browser-like client (headless Chrome,
  Playwright's page context, a tool that adds `Origin`) get `403` unless the
  origin they send is the dashboard's own or is listed in
  `management.cors.allowedOrigins` (or `GATEON_CORS_ORIGINS`).
- A dashboard served from a different origin than the management API must list
  that origin in `management.cors.allowedOrigins`; that is now what lets it
  write, as well as read.

### Management CORS is off unless configured

With no `management.cors.allowedOrigins` and no `GATEON_CORS_ORIGINS`, the
management API now sends no CORS headers at all. It used to answer every origin
with `Access-Control-Allow-Origin: *`. The dashboard is served from the
management origin and never needed it. Every `/v1/*` and Connect response to
a GET, HEAD or POST (the methods a cache may store) now also carries
`Cache-Control: no-store`.

**Who is affected:** a page on another origin that read the management API's
unauthenticated endpoints (`/v1/setup/required`, health) cross-origin. Name its
origin in `management.cors.allowedOrigins`.

### A query-string token is accepted only on a WebSocket handshake

`?token=`, `?access_token=` and `?auth=` used to authenticate any request that
sent `Accept: text/event-stream`, a header any client can send. They are now
read only on a WebSocket handshake (a `GET` with `Upgrade: websocket`,
`Connection: Upgrade` and `Sec-WebSocket-Key`), the one place a browser cannot
send a header. This applies to the management API and to the JWT, PASETO and
OAuth2-introspection route middlewares, which share the rule.

**Who is affected:** server-sent-event clients that put a token in the URL --
of the management API (the dashboard does not; its event stream uses the
cookie) or of an app behind a route with JWT/PASETO/OAuth2 auth. Send the token
in `Authorization: Bearer` (an EventSource polyfill or a fetch-based SSE client
can) or in a cookie.

### Only an administrator may change the global settings that guard the management plane (ADR 0040)

An operator could write the whole global configuration, and the global
configuration holds the security boundary itself. An operator could switch
authentication off and expose the management API on every entrypoint -- after
which an anonymous request reset the administrator's password -- grant
themselves any permission through `rbac`, replace the session key, narrow the
management allowlist to lock administrators out, or switch audit off with no
record that they had.

A save of the global configuration (`PUT`/`POST /v1/global`, `PUT /v1/config`,
gRPC `UpdateGlobalConfig`) by anyone who is not an administrator is now refused
with **403 / `PermissionDenied`, naming the fields**, when it changes any of:

- `auth` (all of it), `rbac` (all), `audit` (all), `management` (all, GitOps
  included), and `log.audit_log_retention_days`;
- `tls.client_auth_type` and `tls.client_authorities` (mTLS trust);
- `waf.trust_cloudflare_headers` (which header names the client address) and
  `waf.audit_log_path` (a file the gateway writes to);
- `redis.addr`, `redis.password`, `redis.db` (switching Redis on or off stays
  an operator's);
- `ebpf.enabled`, `ebpf.interface`, and the eBPF management allowlist and port
  knocking (`enable_mgmt_whitelist`, `mgmt_whitelist_ips`, `enable_knocking`,
  `mgmt_port`, `knocking_sequence`);
- `debugger.enabled` (it captures raw headers and bodies, credentials included).

Everything else stays an operator's. A save that sends these settings back
unchanged -- which is what the dashboard does, secrets as the stored-secret
placeholder or as their `$env:`/`$file:` reference -- is not a change and is
accepted. The "disable public management" AI-advisory fix is
administrator-only for the same reason. Administrators are unaffected.

The check fails closed: a request whose caller cannot be read is not an
administrator, and a request that reaches the save with no identity while
authentication is on is refused for these fields too. With authentication off
the management plane is open by configuration and nothing is restricted.

**Changing the audit settings is now itself audited**, before the change takes
effect: an entry `update` on `audit_config` names each changed audit field (old
and new values for switches and numbers; keys and URLs by name only). Switching
audit off is therefore the last thing the audit log records.

The dashboard shows these settings to operators read-only, with a one-line
reason; the Client Authorities page is read-only for them.

**An entrypoint may no longer be saved with the id `management`.** That id is
how the management plane recognises its dedicated listener, so a data-plane
entrypoint saved under it served the dashboard and the management API on its
own address even with `allowPublicManagement` off. Saving one is refused for
every role (400 over REST). An entrypoint already stored under that id keeps
loading; rename it, or use `management.allowPublicManagement` /
`management.allowedHosts` if exposing the management plane there was intended.

**Who is affected:** deployments where operator accounts changed any of the
settings above -- those changes now need an administrator. Automation that
`PUT`s the global configuration with an operator's credentials must send these
fields back unchanged (or leave their sections out). Nothing changes for
administrators, viewers, or deployments with authentication off.

### The second 2FA sign-in step now requires the challenge from the password step

`POST /v1/auth/2fa/verify` used to take `{id, code}` and nothing else, so an
account id and one TOTP or recovery code signed in with no password. It now also
requires a `challenge`: proof, issued by the gateway, that the account's password
was presented within the last five minutes.

- A correct password on an account with 2FA answers, as before, with no session
  and `twoFactorRequired: true` (or `twoFactorSetupRequired: true` when an
  administrator required 2FA and the account has not enrolled), and now also
  `twoFactorChallenge: "v4.local...."`. Send it back as `challenge` with the
  code: `{"id": "<user id>", "code": "123456", "challenge": "<twoFactorChallenge>"}`.
  The Login RPC answers with the same field.
- Self-service enrolment (`POST /v1/auth/2fa/setup`, signed in, with the current
  password) now answers with a `challenge` as well; send it to
  `/v1/auth/2fa/verify` with the first code. A required enrolment
  (`/v1/auth/2fa/enroll`) uses the challenge from the sign-in that answered
  `twoFactorSetupRequired`.
- A missing, expired (older than five minutes), malformed or other-account
  challenge, or one voided since by a password, role or disabled change or a
  sign-out, is refused with `401` and `"code": "two_factor_challenge_invalid"`:
  sign in again. These refusals do not count towards the account's lockout, so
  the endpoint can no longer be used to lock an account out by its id.
- A challenge is not a session. It is refused as a bearer token everywhere,
  including by a route's PASETO middleware configured with the session key.

The dashboard does all of this itself; nothing changes for people signing in
through it, except that a sign-in left at the code prompt for more than five
minutes goes back to the password. A mistyped code in the Settings enrolment
dialog also no longer signs the user out.

**Who is affected:** scripts and API clients that sign in to an account with 2FA,
or enrol one, through `/v1/login` and `/v1/auth/2fa/verify`. They must read
`twoFactorChallenge` from the sign-in answer (or `challenge` from the setup
answer) and send it as `challenge` with the code; until they do, their verify
calls are refused with 401. Accounts without 2FA are not affected. See ADR 0039.

### A 2FA sign-in gets the account's role, and a disabled account cannot sign in through the second step

A sign-in completed with a TOTP or recovery code issued a session with no role,
which every permission check refuses: an account with 2FA, administrators
included, could sign in to the dashboard but do nothing, and no API turned 2FA
off again. Such a session now carries the account's role.

The second step also never checked whether the account was disabled, so a user
who was disabled while still holding an authenticator or a recovery code could
sign straight back in. A disabled account is now refused there, and no session
is issued or accepted for a disabled account by any path.

**Who is affected:** anyone who enrolled 2FA and found the dashboard refusing
everything after signing in: sign in again after upgrading. Nothing to configure.

### Binding a credential-injecting middleware to a route now needs an administrator

A route that binds a middleware which injects a credential toward the backend --
a `headers` middleware that sets or adds a **request** header under a credential
name (`Authorization`, `Proxy-Authorization`, `Cookie`, `X-Api-Key`, or any name
`secretmask.IsCredentialName` flags), or a `rewrite` middleware that adds a query
parameter under one -- can now be created or changed only by an administrator.

Concretely, a caller with the **operator** role (write on routes/services, but
not admin) is now refused, `403` over REST and `PermissionDenied` over
Connect/gRPC, when they:

- create or edit a route so that it **newly binds** such a middleware; or
- **repoint** a route that carries one to a different service; or
- **repoint the service** (change its targets or discovery URL) that a
  credential-carrying route depends on.

An operator is **not** affected when they:

- manage a route that carries no such middleware (the common case); or
- edit a route an administrator built with such a middleware **without** adding a
  binding and without changing its service (priorities, rules, entrypoints, TLS
  and the like are all still theirs); or
- edit a credential-backed service without changing where it sends traffic.

Administrators are unaffected and may do all of the above. Deployments running
with authentication **off** are unaffected -- there is no operator/administrator
distinction to enforce.

The same refusal applies to a config **import** performed by an operator: a route
in the imported config that binds a credential-injecting middleware is rejected
(named in the per-item errors), while the rest of the import proceeds.

**Who is affected:** operators (role `operator`) who today attach an
auth-injecting `headers`/`rewrite` middleware to a route, or repoint such a route
or its service. They must have an administrator make or change that binding.
Nothing else about route or service management changes. See ADR 0038.

### A block now ends an address's open L4 sessions, not only its new connections

Blocking an address -- by hand, or automatically -- now closes that address's
**already-open** connections on every TCP entrypoint (SSH, database, mail and
other L4 sessions), not only the connections it opens afterwards. Before, an
open L4 session ran until its client ended it, because an L4 session has no
request boundary at which the block would take effect; only new connections were
refused, and only eBPF (where present) dropped an open session's packets. The
close honours the mitigation allowlist: an address on
`GATEON_MITIGATION_ALLOWLIST` (or loopback) that an operator also blocks is not
cut, exactly as the accept-time check leaves it served.

**Who is affected:** operators running non-HTTP (L4) routes -- SSH, databases,
SMTP/IMAP/POP3, and similar -- through TCP entrypoints. If you block or shun an
address, its live sessions now end promptly instead of lingering. No
configuration change is required. HTTP entrypoints are unchanged: an open
connection from a blocked address is still refused at its next request.

### New per-source-address connection cap on every entrypoint

Every entrypoint now limits how many concurrent connections one source address
may hold, so a single client cannot fill an entrypoint by opening many
connections. This complements the existing entrypoint-wide `max_connections`
(both apply; the per-address cap is the tighter for one client) and the existing
`GATEON_MAX_CONN_PER_IP`, which counts requests in flight rather than
connections. The default is per tier: **128** (minimal), **256** (standard),
**1024** (enterprise). Set `GATEON_ENTRYPOINT_MAX_CONN_PER_ADDR` to override it,
or to `0` to disable it. Loopback and `GATEON_MITIGATION_ALLOWLIST` are exempt,
so a gateway behind a local reverse proxy -- where every client appears as
loopback -- is not capped by the one address it shares. A connection past the
cap is closed at accept and counted with the other connection-limit rejections
(`inflight_rejected.max_connections` on the Diagnostics limit card).

**Who is affected:** every deployment. A legitimate client behind a large shared
NAT that opens more than the per-tier default of concurrent connections to one
entrypoint would see connections past the cap refused; raise
`GATEON_ENTRYPOINT_MAX_CONN_PER_ADDR` for such a deployment. A gateway placed
directly behind a single reverse proxy or load balancer with no PROXY-protocol
input sees all traffic as one address (the proxy's); if that address is not
loopback, set `GATEON_ENTRYPOINT_MAX_CONN_PER_ADDR=0` or allowlist the proxy so
its aggregated connections are not capped as one client's.

### The kernel shun map now honours GATEON_MITIGATION_ALLOWLIST and loopback

The eBPF shun map (where XDP/TC drops a blocked address's packets) now applies
the same exemption every HTTP and TCP entrypoint already applies: an address in
`GATEON_MITIGATION_ALLOWLIST`, or a loopback address, is never pushed to the
kernel shun map, even when an operator has explicitly blocked it. Before, the
kernel dropped such an address even though every other path served it (the gap
ADR 0032 left open under "still not uniform: the kernel").

The block itself is still recorded and still appears in the mitigation list --
the allowlist exempts *enforcement*, not the record of the operator's decision.
Automatic shuns already honoured the allowlist and are unaffected.

**Who is affected:** deployments running the eBPF data plane (`ebpf.enabled`)
that also configure `GATEON_MITIGATION_ALLOWLIST` **and** hand-block an address
they have allowlisted. On those, such an address is now served in the kernel as
it already was in user space. No configuration change is required.

**One residual to know:** if you hand-blocked an address *before* adding it to
the allowlist, the kernel entry placed at block time is not swept out
automatically. Release that block (or restart) to clear the kernel entry;
automatic shuns clear themselves as their lease lapses. This affects only a
manual block of an address later allowlisted.

### A manual IP block may carry an optional duration

The mitigate API (`MitigateThreatRequest`) gains an optional `duration_seconds`
field, and the Security Center's Add Mitigation control gains a Duration choice
for an IP block (until released, 1 hour, 6 hours, 24 hours, 7 days). A block
given a positive duration lapses on its own that many seconds after it is
applied -- it is listed with a countdown to when it lifts and needs no operator
to release it. A block with no duration (or `duration_seconds = 0`) holds until
released, exactly as every manual block did before. The duration applies only
to an IP block; a fingerprint block keeps its own hour-long TTL.

**Who is affected:** anyone scripting the mitigate API who wants a time-boxed
block can now set `duration_seconds`; existing callers that omit it are
unchanged. No configuration or migration is required -- the change reuses the
`ip_mitigations.expires_at` column added in the previous release.

### The API-key fingerprint is stable across a restart without an encryption key

The dashboard shows a stored apikey-middleware API key as a placeholder marker
that carries a fingerprint, and saving the form sends the marker back to keep
the stored key. When `GATEON_ENCRYPTION_KEY` was unset, that fingerprint was
random per process, so a form opened or a config exported before a restart
could no longer be saved afterward -- every API key in it was refused ("no
stored API key has this fingerprint"). The fingerprint is now stable across a
restart when no encryption key is set, so such a save succeeds.

**Who is affected:** deployments that run the apikey middleware **without**
setting `GATEON_ENCRYPTION_KEY`. Setting `GATEON_ENCRYPTION_KEY` was, and
remains, the way to get per-install fingerprints that a leaked masked config
cannot be tested against offline; its behaviour is unchanged. Deployments that
already set it see no difference.

### A middleware resolves a secret reference only where the host allows — **set `GATEON_MIDDLEWARE_SECRET_REFS` if a middleware uses one**

A middleware's fields resolve `$env:`, `$vault:` and `$aws-sm:` references, and a
middleware is written by an operator, not only an administrator. Nothing
constrained it: an operator could name any secret the process can reach -- the
encryption key, a database password, a session key held as a reference -- and
read it back through a response header, or send it to a URL the middleware
names. Now a reference is resolved only when it is in a field that holds a
secret (not one whose value is echoed to the client) **and** the host has listed
it in `GATEON_MIDDLEWARE_SECRET_REFS`, a comma-separated list of the exact
references a middleware may use, read from the environment where the API cannot
write it. Unset, no middleware field resolves a reference.

A middleware whose field holds a reference that is not allowed is refused, and
its route serves the refusal it serves for any security middleware it cannot
build; the error names the reference and the variable. A literal or encrypted
secret in a field is not a reference and is unaffected. The global
configuration's own fields, which only an administrator writes, are unchanged.
See ADR 0034.

**Who is affected:** an install that uses `$env:`, `$vault:` or `$aws-sm:` in a
middleware field (a JWT/HMAC secret, an OAuth client secret, an API key). List
those references in `GATEON_MIDDLEWARE_SECRET_REFS`, or put the values in
directly, before upgrading. A middleware with no such reference needs nothing.

### Automatic IP shuns lapse, and a released address can be shunned again after a day

Every address the gateway shunned on its own -- the address shun (five
attacking client builds within ten minutes), the anomaly detector's brute-force
and exploit-scanning shuns, an alert playbook's "block", the alerting
manager's autonomous mitigation, and the incident responder's opt-in hard
shun (`GATEON_MITIGATION_AUTO_SHUN`) -- used to hold until an operator released
it. It now lapses: the first shun of an address lasts **15 minutes**; an
address shunned again within 24 hours of its last shun lapsing is shunned for
twice as long as last time, up to **24 hours** (15m, 30m, 1h ... 16h, 24h).
After a day with no shun the next one starts at 15 minutes again. A lapsed shun
stops refusing the address at once, and leaves the kernel's shun map (with
eBPF) within 30 seconds. The IP mitigation list shows when each automatic shun
lifts ("lifts in 42m"), as it does for kernel throttles, and stops listing it
once it has.

A shun you place yourself -- Mitigate on a threat, or an applied
recommendation -- is unchanged: it holds until you release it, and no
automatic shun shortens it.

**Releasing an address (Allow) now holds for a day, not forever.** For 24
hours no automatic path shuns it again; after that, fresh attack evidence can
shun it again, starting at 15 minutes. To exempt an address permanently, put
it on `GATEON_MITIGATION_ALLOWLIST`. Releases made before the upgrade are
measured from when they were made, so an address released more than a day
before upgrading can be shunned again by new evidence.

**At the upgrade** (migration 66, `ip_mitigations.expires_at`), a shun written
before it by an automatic path is given the expiry it would have had -- 15
minutes after it was written -- so nearly all of them lift when the upgraded
gateway starts. They were earned under rules the gateway no longer uses (three
JA4+ strings, with rate-limit refusals counted); an address still attacking is
shunned again within minutes. Automatic shuns are recognised by the reason they
were written with ("IP shunning triggered", "Anomaly detection:", "Alert
playbook:", "Autonomous mitigation", "correlated critical incident:"); every
other shun -- yours -- keeps no expiry.

A shunned address's refused requests no longer count as refused login
attempts. Without eBPF, a shunned address is refused with a 403 by the gateway
itself, and a POST refused 403 used to count as a refused credential attempt,
so an office shunned by mistake whose users kept submitting forms looked like
it was still guessing passwords. The same applies to requests refused because
their client build is blocked, or out of reputation, on their network.

The gateway no longer shuns an address in the kernel when the reputation kept
under the bare address (threats with no client fingerprint, such as the anomaly
detector's) falls below 20. That shun was never listed, could not be released
from the list, ignored the allowlist and never lapsed; the detectors behind
those threats shun or throttle an address themselves.

**Who is affected:** anyone with addresses on the IP mitigation list that an
automatic path put there (they lift at the upgrade unless re-earned), anyone
who released an address and relied on the release being permanent (use
`GATEON_MITIGATION_ALLOWLIST`), and eBPF deployments whose kernel shun map held
addresses from low reputation (they are no longer added).

### An allowlisted source's threats no longer lower its network's reputation

A threat from an address on `GATEON_MITIGATION_ALLOWLIST` used to lower the
reputation score its client build holds on its /24 (or /64) -- kept as
"observation" -- and the reputation blocker refuses every client of that build
on that network once the score falls. An allowlisted scanner therefore got its
neighbours running the same browser or TLS stack refused. Its threats now move
no score, from the recording path or from the incident responder's penalty for
every address in an incident. They are still recorded, listed, correlated and
alerted on.

**Who is affected:** deployments with `GATEON_MITIGATION_ALLOWLIST` set whose
allowlisted sources produce threats (scanners, pentest teams, monitoring):
clients sharing their network and client build are no longer refused for them.

### Expired sessions and tokens polled over POST are no longer read as password guessing

Both brute-force detectors (the opt-in anomaly detection's brute-force check,
which can shun, and the analysis engine's per-address findings) counted every
POST refused 401 or 403 as a refused credential attempt. GraphQL, gRPC-Web and
Connect clients poll with POST -- the dashboard's own calls are Connect -- so a
dashboard tab left open after its session expired, or an API client
re-presenting an expired token, looked like someone guessing passwords, and
with brute-force detection on it could be shunned.

When the gateway's own verification refuses a token a request presented -- the
dashboard/management session, or a route's PASETO, JWT, API key or OAuth2
introspection middleware finding it invalid, expired, revoked or short of the
route's scopes -- the refusal is no longer counted as a credential attempt.
Traces record it (`refusal: "token"` in the stored trace). A request that
presented no token, a middleware in dry run, and a refusal made by the backend
itself are counted as before; so are logins refused by a password check, even
if the request also carries an `Authorization: Bearer` header, and HTTP Basic
or Digest guesses.

**Who is affected:** deployments with anomaly brute-force detection on, whose
API clients or dashboard tabs poll with expired tokens: they are no longer
reported or shunned for it. Guessing API keys over POST is no longer counted by
the brute-force detectors; each guess is still refused by the key check.

### Every HTTP entrypoint holds at most max_connections at once — a new default cap

`max_connections` was read by TCP entrypoints only. An HTTP entrypoint held as
many connections as clients cared to open -- an idle keep-alive connection for
a minute, a silent one for ten seconds before its first header -- so a flood of
connections, which cost the client one packet each, cost the gateway a
goroutine, buffers and a descriptor each without bound.

Every HTTP entrypoint -- plaintext and TLS, HTTP/1, HTTP/2 and HTTP/3 -- now
holds at most `max_connections` connections at once, or, with `max_connections`
at 0 (the default, and what every existing entrypoint has), the resource
profile's limit: **1000** (`minimal`), **10000** (`standard`), **50000**
(`enterprise`), selected by `GATEON_PROFILE` as for every other profile
default. What counts is a connection, not a request:

- an idle keep-alive connection counts for as long as it stays open (up to the
  one-minute idle timeout);
- an HTTP/2 connection counts once, however many requests it carries at once
  (up to 250 streams per connection, as before);
- on an HTTP/3 entrypoint, a QUIC connection counts once, and QUIC and TCP
  connections share the entrypoint's one limit.

A connection past the limit is closed as soon as it is accepted -- on a TLS
entrypoint before its handshake -- and a QUIC connection past it is closed
with `H3_EXCESSIVE_LOAD`. Refusals are counted with the other connection-limit
rejections on the Diagnostics limit card (`max_connections`), and logged at
WARN at most once a minute per entrypoint (`HTTP entrypoint at its connection
limit, refusing new connections`). The limit is read when the entrypoint
starts, so a change takes effect after a restart.

The dedicated management listener is not capped and takes no slot from any
entrypoint: a flood that fills a data-plane entrypoint leaves the dashboard and
the management API reachable.

The dashboard's entrypoint form now shows **Max Connections** for every
entrypoint (it kept the value but had no input for it) and says what 0 means.
On a UDP entrypoint without TLS, which has no connections, the field is
disabled and says so.

**Who is affected:** an HTTP entrypoint that holds more concurrent connections
-- idle keep-alive ones included -- than its profile's default: more than 10000
on the standard profile, 1000 on minimal. Clients past it see their
connection closed. Set `max_connections` on the entrypoint (dashboard, config
file or API). Behind a load balancer that pools connections to the gateway,
count the pool's connections, not its clients.

### A TCP entrypoint refuses addresses on the IP mitigation list

A shunned or manually blocked address was refused by every HTTP entrypoint and,
where eBPF ran, dropped in the kernel -- and without eBPF connected to a TCP
entrypoint as freely as any other: to an SSH, database or mail backend, and on
a tcp-only entrypoint straight to its backend.

Every TCP entrypoint -- plaintext or TLS-terminating, inspected or tcp-only --
now closes a connection from an address on the list as soon as it is
accepted, before reading from it or starting TLS. The client sees the
connection closed; the backend never sees it. Each refusal is recorded like
an HTTP one, as an `ip_mitigation` threat in the Security Hub (and on
`gateon_middleware_advanced_security_blocked_total`), with details naming the
TCP entrypoint. Releasing the address lets its next connection through. A
block reaches connections accepted after it: an L4 session already open when
its address is blocked runs until it ends (eBPF, where it runs, also drops
that session's packets).

Addresses exempt from enforcement are served on TCP entrypoints as on HTTP
ones: loopback and those `GATEON_MITIGATION_ALLOWLIST` names. **This also
changes HTTP entrypoints:** they used to refuse an allowlisted or loopback
address that was on the list; they now serve it, as the fingerprint and
reputation blocks already did. No automatic path shuns such an address, so this
affects only an operator's explicit block of an address that is also on the
allowlist, and blocks made before the upgrade. Where eBPF runs, the kernel
still drops such an address.

**Who is affected:** anyone with addresses on the IP mitigation list and TCP
entrypoints: those addresses can no longer reach L4 backends. A TCP
entrypoint behind a proxy or load balancer sees the proxy's address, not the
client's (there is no PROXY-protocol input), so blocking the proxy's address
blocks everyone behind it -- as it always did on HTTP without trusted proxies.
And anyone who blocked an address they had also allowlisted: HTTP entrypoints
now serve it.

### Middleware secrets are no longer returned by the API — **API clients and exports that read them stop getting them**

Anyone who could write middlewares -- administrators and operators, or anyone
when authentication is off -- read every middleware secret verbatim: basic-auth
passwords, JWT, PASETO and HMAC keys, OAuth introspection and OIDC client
secrets, turnstile, bot-management and proof-of-work secrets, canary tokens and
API keys, over REST and gRPC, in the answer to a save, and in
`GET /v1/config/export`. Middleware secrets are now write-only, like the global
configuration's (ADR 0028). See ADR 0033.

- A stored middleware secret reads as `__gateon_redacted__`; a secret configured
  as a reference (`$env:…`, `$vault:…`, `$aws-sm:…`) still reads as the reference
  to administrators and operators; an unset one reads `""`.
- A basic-auth user list reads as `alice:__gateon_redacted__,bob:__gateon_redacted__`.
  Each password is kept by the user's name.
- An API key reads as `key___gateon_redacted___<fingerprint>` with its tenant label
  as the value. Sending that entry back keeps the key under whatever label it
  now has; leaving it out removes the key.
- A value the headers middleware sets for a header whose name carries a
  credential -- `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, or
  any name containing `token`, `secret`, `passw`, `key`, `auth`, `session`,
  `credential`, `signature`, `bearer` or `jwt` -- and a query parameter the rewrite
  middleware adds under such a name, are secrets too.
- **GET → modify → PUT keeps working.** Send the placeholders back unchanged and
  every stored secret is kept exactly as it is held. A new value replaces a
  secret; `""` clears it, and a secret the middleware cannot run without is then
  refused by the save, naming it.
- The placeholder is refused, naming the field, when there is nothing to keep:
  for a new middleware id, for a field that holds no secret, and when the same
  save changes the middleware's type or kind of authentication, its OAuth
  introspection URL, its OIDC issuer or its forward-auth address. Enter the
  secret again in those cases. A renamed basic-auth user needs its password
  again.
- No store accepts the placeholder as a value, and a middleware whose stored
  config holds it (a hand-written `middlewares.json`, or one seeded from an
  export) is not built: the route refuses requests until the secret is entered.

**Who is affected:** API clients and scripts that read middleware secrets from
`GET /v1/middlewares`, `ListMiddlewares` or the config export -- they now get
placeholders. Operators who used the config export as a backup of middleware
credentials: it no longer carries them, and there is no export that does; back
up the database or `middlewares.json` on the host instead. Deployments without
`GATEON_ENCRYPTION_KEY`: API-key fingerprints change on every restart, so an
export taken, or a dashboard form opened, before a restart cannot keep API keys
-- the import or save names each one to enter again. Viewers: they no longer see
any value the headers or rewrite middlewares set.

### Config export carries no middleware secret; import keeps them on the same gateway

`GET /v1/config/export` writes every middleware secret as the placeholder.
`POST /v1/config/import` of such an export into the same gateway keeps the
stored secret of each middleware with the same id, type and destination, and
refuses -- naming the middleware and the field -- a placeholder it cannot keep,
while importing everything else. The preview (`?dry_run=true`) lists those under
`"refused"` before anything is written, and no longer echoes the secrets it was
sent; neither does `POST /v1/config/validate`.

**Who is affected:** anyone moving middlewares between gateways with export and
import: middlewares with secrets need them entered on the target (an export
into a gateway whose middleware ids happen to match keeps that gateway's own
secrets).

### A session key changed outside the dashboard no longer locks out every 2FA account — **set `GATEON_PREVIOUS_SESSION_KEY` when you rotate the key at its source**

The session key also encrypts each stored second factor, and only a rotation
from Settings re-encrypted them. A key changed any other way -- `global.json`
edited, the secret a `$vault:`, `$aws-sm:` or `$env:` reference names rotated
at the source, a cluster instance restarted with its peers' new key -- left
every two-factor account unable to complete a sign-in, and nothing in the log
said why. At startup the gateway now checks every stored second factor against
its key and logs an error with the number it cannot decrypt; with
`GATEON_PREVIOUS_SESSION_KEY` set to the previous key, it re-encrypts them
under the new one in one transaction. The previous key only decrypts second
factors: it never verifies a session. Second factors stored in plaintext, from
before they were encrypted at rest, are encrypted at the same startup.

**Who is affected:** anyone who rotates the session key outside Settings, and
deployments with several instances sharing a user database -- see "Rotating
the session key" in `doc/security-posture.md`. Remove the variable once an
instance has logged that it re-encrypted them.

### `ebpf.af_xdp_phantom` is removed

Field 11 is reserved. The setting was read by nothing but the TC fallback's
list of features it cannot enforce. The XDP program redirected packets for any
port listed in its `phantom_ports` map to an AF_XDP socket, but nothing ever
wrote that map or opened a socket, so the only effect was a hash lookup on
every TCP and UDP packet. Both maps are gone. A stored config that still sets
the key loads as before; the key is ignored. The Diagnostics Phantom Core card
is unaffected: it reports the kernel splice path, which never used XDP.

### Stored secrets are no longer returned by the API — **API clients that read secrets stop getting them**

`GET /v1/global` and `GetGlobalConfig` returned every stored credential to any
caller who may write the global configuration: the PASETO key that signs
sessions, the audit chain's HMAC key, the database, Redis and HA passwords, the
MaxMind key, the GitOps token, the bot-management and proof-of-work secrets, the
canary token, the IP-reputation API keys and the alert webhook URLs and Telegram
bot tokens. One stolen administrator session was enough to mint a session for
any account. Secrets are now write-only. See ADR 0028.

- A stored secret now reads as `__gateon_redacted__` (the placeholder the
  middleware API already uses); a secret configured as a reference (`$env:…`,
  `$vault:…`, `$aws-sm:…`) still reads as the reference; an unset one reads `""`.
  A database or repository URL shows everything but its password:
  `postgres://gateon:__gateon_redacted__@db/gateon`.
- **GET → modify → PUT keeps working.** Send the placeholders back unchanged and
  every stored secret is kept exactly as it is held.
- **To rotate a secret, send the new value.** `""` clears an optional credential;
  the session key, the audit signing key and the proof-of-work key cannot be
  cleared, and `""` keeps them.
- A kept secret is refused, with `400` and the field's name, when the same save
  changes where it is sent: the Redis address, a database's driver, host or port,
  the GitOps repository's host, an IP-reputation integration's provider. Send
  the secret again with the new destination.
- Secrets in alert dispatchers and IP-reputation integrations are matched to the
  stored element by `id`. A placeholder in an element whose `id` is missing or
  unknown is refused with `400` naming the element. Elements stored without an
  `id` get one when the configuration is loaded; read it before you save.
- The placeholder is never stored as a secret: a save that would store it is
  refused, whatever path it comes by.
- Viewers still read every secret as `""`.

**Who is affected:** scripts and tools that read credentials out of
`GET /v1/global` or `GetGlobalConfig` (they now get the placeholder), and anyone
who relied on the dashboard to show a stored key. Keep your own copy of any key
you need to see again; the gateway will not show it.

### A new session key takes effect when it is saved — **saving a new key signs everyone out at once**

A PASETO key changed in Settings (or through the API) used to take effect only at
the next restart, and that restart also broke every two-factor sign-in, because
stored second factors are encrypted under the same key: 2FA accounts, the
administrator who rotated included, could no longer sign in. The new key now
takes effect as soon as it is saved: every session ends immediately, yours
included, and every two-factor enrolment is re-encrypted under the new key and
keeps working. A key shorter than 32 bytes is refused (`400`) instead of being
saved and failing the next start. The dashboard asks before it lets you replace
the key, and says what will happen.

**Who is affected:** anyone who rotates the session key. If several gateway
instances share one user database, give every instance the new key and restart
them; until then the others keep accepting sessions signed with the old key,
and their two-factor sign-ins fail.

### Rotating the audit signing key — **older entries verify only with the old key**

The dashboard now asks before replacing the audit signing key, because entries
written before the change verify only with the old key, which the gateway no
longer shows. If you will need to verify them, copy the key from `global.json`
on the gateway host before you save the new one.

**Who is affected:** installs with audit signing on that rotate its key.

### Alert and startup logs no longer carry credentials

A failed alert send logged the webhook URL or Telegram bot URL, which is the
credential; the startup log line for a path-stats store that could not open
carried the auth database URL with its password. Both are now logged without
the secret. The log stream is readable by viewers, so a credential that reached
it was readable by them.

**Who is affected:** nobody needs to change anything. If your logs are shipped
somewhere, rotate any webhook, bot token or database password that may be in
older log lines.

### An address is shunned automatically only when five client builds behind it attack — **fewer automatic IP shuns**

Besides blocking a fingerprint, every recorded threat could shun its source
address: a row on the IP mitigation list, refused with `Forbidden: IP Shunned
by Security Policy` on every entrypoint and route and dropped in the kernel when
eBPF runs, until an operator releases it -- it does not expire. The shun was
triggered by three different JA4+ fingerprints behind one address with any
refused request, and the count never lapsed. A JA4+ changes with a request's
method and whether it sent a cookie or a `Referer`, so one browser whose
requests the WAF refused could shun its own address; rate-limit rejections, geo
and bot-policy blocks and reputation blocks counted as if they were attacks, so
three browser builds behind an office egress that each hit a rate limit shunned
the office; and `GATEON_MITIGATION_ALLOWLIST` was not consulted.

An address is now shunned automatically when five different client builds --
the fingerprint's class, the part a client cannot vary per request, as for
fingerprint blocks -- each produce attack evidence from it within ten minutes:
a WAF block on a payload, a trap, a malware upload, a brute-force or
exploit-scan detection. Rate limits and policy blocks never count. A build
counts for ten minutes after its latest attack. Allowlisted addresses are never
shunned by this path, and nothing they do while allowlisted is held against
them afterwards. Fewer than five attacking builds -- an office with a few
infected machines, say -- are handled build by build: each is blocked on its
network by the fingerprint block after three attacks in ten minutes, and the
address stays up (ADR 0029). There is no new setting.

- The reason on an automatic shun reads `IP shunning triggered: attack evidence
  from 5 different client builds at this address within 10m0s` (it used to read
  `... N unique malicious users detected from this IP`).
- Releasing an address still exempts it from the automatic shun from then on,
  and now also discards the evidence gathered against it.
- Shuns already on the list are not touched.

**Who is affected:** installs behind which many users share an address (office
egress, CGNAT, VPN exits): far fewer automatic shuns. A client that changes its
TLS fingerprint on every connection is shunned at its fifth within ten minutes.

### The mitigation allowlist and loopback are exempt from fingerprint blocks

A fingerprint block (the "User Mitigations" list, refused with `Forbidden:
Compromised Fingerprint`) refused clients on `GATEON_MITIGATION_ALLOWLIST`, and
loopback clients, whenever their browser build was blocked on their network --
typically by someone else's attacks, since a block covers a build on a /24 or
/64. The reputation blocker already served both; the fingerprint block now
serves them too. Threats from allowlisted addresses are still recorded, listed
and correlated, but no longer count towards an automatic fingerprint block or
an automatic IP shun: a block earned by an allowlisted scanner refused its
neighbours running the same build.

**Who is affected:** installs that set `GATEON_MITIGATION_ALLOWLIST` (an
operator's own scanners, monitoring or office egress), and installs behind a
local proxy that sets no forwarding header, where every client is loopback.
An allowlisted address's threats still lower its build's reputation on its
network, as before.

### Brute-force detection counts login attempts, not every 401 and 403 — **an expired dashboard tab is no longer shunned**

With `anomaly_detection.enable_brute_force_detection` on, the anomaly detector
counted every 401 and 403 an address received as a failed login, and shunned
the address when they were over 80% of its requests. A dashboard tab left open
after its session expired -- every poll a GET answered 401 -- was shunned
within a check interval, and so was a client refused 403 on GETs by a policy or
the WAF. It now counts credential attempts refused 401 or 403: POSTs, and any
request whose `Authorization` header carries a password (HTTP Basic or Digest),
the rule the per-IP threat detector already uses. A GET that re-presents an
expired session cookie or bearer token is not counted. Exploit scanning is
still detected from WAF blocks, by its own check.

**Who is affected:** installs with brute-force detection enabled (it is off by
default). Credentials guessed through a GET query string are not counted, and a
client that POSTs into a 401 or 403 most of the time still is -- including a
GraphQL or gRPC-Web client that keeps polling with an expired bearer token.

### gRPC on a plaintext TCP entrypoint is authenticated — **upgrade if you run one**

On a plaintext TCP entrypoint, gRPC and gRPC-Web went straight to the gateway's
own gRPC server, past the handler that authenticates the management API. The
server's permission check read "no caller" as "authentication is off", so anyone
who could reach the port could call the management API with no credential,
`UpdateGlobalConfig` included. That traffic now goes through the same handler as
everything else. A permission check also refuses a request that carries no
caller unless that handler decided the request needs none. See ADR 0027.

**Who is affected:** every install with a TCP entrypoint that is not TLS, on
every release so far (the dispatch dates from v0.1.0). Nothing needs changing,
but upgrade. Until you can, stop such an entrypoint being reachable from anywhere
you do not trust. A gRPC route on such an entrypoint is now proxied to its
backend; before, the gateway's own server answered it.

### Signing out ends every session of the account — **a sign-out now signs out every device**

Signing out cleared the browser's cookie and nothing else. The session token
the cookie held is a bearer token, and it went on working until it expired --
up to eight hours -- for anyone holding a copy of it. Signing out now advances a
per-account session epoch that every session is bound to, so every session of
the account ends: the one that signed out, any copy of its cookie, and the
account's sessions in every other browser and API client. Signing in again
works as before. The dashboard's sign-out controls (the profile menu, the
Profile page and the command palette) now say that sign-out ends every session
of the account.

Migration 65 adds `users.session_epoch` (`INTEGER NOT NULL DEFAULT 0`) on SQLite
and Postgres. Every existing account starts at 0, which the session binding
leaves out, so the upgrade ends no session and tokens issued before it keep
working.

In a cluster, the node that handles the sign-out refuses the account's old
sessions at once; the other nodes follow within the session-binding cache TTL
(30 seconds, `GATEON_SESSION_BINDING_TTL`), or within a round trip where the
Redis invalidation channel is configured. During a rolling upgrade, nodes still
on the previous release do not read the epoch: until they are upgraded they keep
accepting a signed-out session, and they refuse the sessions an upgraded node
issues to an account after that account has signed out.

**Who is affected:** anyone signed in to one account from more than one place --
signing out in one browser now signs the others out too -- and automation that
shares an account with a person: its token ends when that person signs out. Give
scripts and API clients an account of their own. A failed sign-out (the gateway
could not record it) now answers 500 and says the account's other sessions
could not be ended; the browser's cookie is cleared either way, and the
dashboard opens the sign-in page with a warning that the other sessions may
still be signed in and how to end them. A sign-out that never reached the
gateway leaves the dashboard where it was and says so, so it can be tried
again.

### Add User refuses a username that is taken — **it used to take that account over**

`PUT /v1/users` (the dashboard's Add User and Edit User) and the `UpdateUser`
RPC wrote accounts with `INSERT ... ON CONFLICT(username) DO UPDATE`, so adding
a user under a username that already existed replaced that account's password
and role and reported success: an administrator who typed a colleague's name
into Add User took their account over. A request with no id, or with an id no
account has, is now a create, and a username another account has is refused --
`409 Conflict` over REST, `ALREADY_EXISTS` over gRPC -- with nothing written;
the dashboard says "That username is already taken by another account. Choose
a different username." and keeps the form open. A request carrying an existing
account's id edits that account, and renaming it onto a taken username is
refused the same way. Renaming a user now works; it used to fail with a
database error.

**Who is affected:** scripts that call `PUT /v1/users` without an id to reset an
existing account's password or role. Send the account's `id` (from
`GET /v1/users`) to edit it; without one the request is a create, and a taken
username is refused.

### Editing a user no longer enables a disabled account — **check your disabled accounts**

The Users page's Edit form saved only the account's name and role, and the
gateway writes the disabled flag and the "must set up 2FA" requirement from
every save. So changing a disabled account's role or name enabled it again,
and changing an account you had required to set up 2FA dropped that
requirement. The form now keeps both.

**Who is affected:** anyone who used Edit on a disabled account, or on one
required to set up 2FA. Check the Users page: an account you disabled that
shows no Disabled badge, or one you required 2FA of that shows no "2FA pending",
was changed by an edit. Disable it or require 2FA again. Scripts that call
`PUT /v1/users` are unaffected: the gateway still sets both flags from what
the request sends, as it always has.

### A browser signing in over gRPC gets no token in the reply

`POST /v1/login` has answered a browser -- a request carrying `Sec-Fetch-Mode`,
which every browser sends and page script cannot remove -- with the session
cookie alone. The `Login` RPC answered every caller with the session token in
its reply, and a browser can make that call: script on the dashboard's origin
sending `application/grpc` over HTTP/2 to an HTTPS management listener. `Login`
over gRPC now withholds the token from a call carrying `Sec-Fetch-Mode`; the
sign-in otherwise succeeds and the reply still names the user. Native gRPC
clients never send that header and still receive the token. gRPC-Web cannot
call `Login` at all -- the management server refuses `application/grpc-web`
with 415 before any RPC runs -- so there was nothing to withhold there.

**Who is affected:** only code running in a browser that signs in over gRPC; it
gets no token and must sign in through `POST /v1/login`, which sets the session
cookie. The dashboard, API clients and gRPC libraries are unaffected.

### A fingerprint block covers one browser build on one network — **existing fingerprint blocks are released on upgrade**

A fingerprint block (the "User Mitigations" list, refused with `Forbidden:
Compromised Fingerprint`) was kept for the whole JA4+ fingerprint, which names
a browser build rather than a client: three WAF blocks from one attacker's
stock Chrome refused every user of that Chrome build, on every network, for an
hour. Rate-limit rejections, bot and geo policy blocks and reputation blocks
counted towards it as if they were attacks, the count never lapsed, and the
attacker shed the block by dropping a `Referer` header, which changes the
fingerprint and not the browser.

A block is now kept for the fingerprint's class -- its TLS fingerprint, or its
header shape without the method, cookie and referer -- on the client's /24
(IPv4) or /64 (IPv6), the identity reputation already uses (ADR 0026). It
refuses that build on that network only, and a header toggle does not shed it.
The automatic block needs three pieces of attack evidence -- WAF blocks on a
payload, traps, malware uploads, brute-force or exploit-scan detections -- from
one build on one network within ten minutes; rate limits and policy blocks no
longer count. The one-hour expiry, `GATEON_JA4_MITIGATE_AFTER` and
`GATEON_JA4_MITIGATION_TTL` are unchanged.

- The user mitigation list shows each block as `<fingerprint class>|<network>`,
  e.g. `t13d1516h2_8daaf6152771_b0da82dd1658|203.0.113`, and only blocks still
  in force. Allow on a row lifts that one network's block.
- Remove Mitigation with a fingerprint -- from a threat's detail view, or
  `POST /v1/diagnostics/remove-mitigation` with the fingerprint as `source` --
  lifts that browser build's block on every network it is blocked on, and holds
  it for 24 hours, as before.
- Add Mitigation (and `POST /v1/diagnostics/mitigate`) takes a fingerprint only
  with a network: `<fingerprint>|<address>` blocks it on that address's /24 or
  /64. A bare fingerprint is refused with that instruction. The dashboard now
  shows a refused block as "Not blocked" with the reason, where it used to show
  a green "Success".
- "Apply automatic fix" on a finding whose source is a fingerprint (impossible
  travel) is refused rather than blocking the build everywhere; on a finding
  with a threat, it blocks the threat's address and the threat's build on the
  threat's network.

**Who is affected:** anyone with fingerprint blocks in force at upgrade time.
They were stored without a network, so they cannot be moved to the new form;
they stop being enforced and listed immediately and are deleted a day later.
Every one would have expired within the hour anyway, and a client still
attacking is blocked again after three more attacks. Scripts that block a bare
fingerprint through the API must add `|<address>`.

### A tab left open after its session expired is no longer reported as brute force

The per-IP threat detector counted every 401 and 403 an address received as a
failed login, so a dashboard tab polling after its session expired -- every
poll a GET answered 401 -- was recorded as a `brute_force_attempt` within a few
minutes, and its score cost the client reputation. Brute force is now judged
on credential attempts only: POSTs (a login form, a token request), and any
request whose `Authorization` header carries a password (HTTP Basic or Digest),
which keeps Basic-auth guessing over GET visible. A client re-presenting an
expired bearer token or session cookie is not an attempt. Traces record whether
a request carried a password scheme (`passwordAuth`; nothing of the credential
is stored).

**Who is affected:** installs where browsers or API clients poll with expired
sessions: fewer `brute_force_attempt` findings. Credential guessing through a
GET query string is not counted.

### Kernel throttles on the mitigation list count down to when they lift

A kernel rate limit on the IP mitigation list gave its expiry only inside the
description. It now carries it as a field (`expires_at` on the listed
`Anomaly`, RFC 3339 UTC), and the list shows "lifts in 4m" under the row's
status, which stays current while the page is open.

**Who is affected:** nobody needs to act. API clients reading the mitigation
list can use `expiresAt` instead of parsing the description.

### Plaintext TCP entrypoints proxy protocols in which the server speaks first — SMTP, POP3, IMAP, FTP, MySQL

A plaintext TCP entrypoint reads each connection's first bytes to choose
between its HTTP server, an `ssh` or `rdp` route and its `tcp` route. A client
of a server-first protocol sends nothing until it has the server's greeting,
so the entrypoint waited for the client while the client waited for the
server: after a second it wrote its own banner line and closed the
connection, and the backend was never dialled. SMTP on 25 and 587, POP3,
IMAP, FTP, MySQL and VNC could not be proxied through a plaintext TCP
entrypoint at all, although `doc/email-backend-setup.md` described exactly
that setup. They now work, in one of two ways depending on what else the
entrypoint serves.

**An entrypoint whose only route is a `tcp` route** has nothing to tell apart,
so each connection goes to the route the moment it is accepted: no detection,
no delay, the backend's greeting arrives at once (measured: under a
millisecond on loopback, the direct connection plus the proxy's own dial).
Everything the client sends is the backend's -- an HTTP request to such a port
reaches the tcp backend, not the gateway's HTTP handling.

**An entrypoint that also serves HTTP, gRPC, `ssh` or `rdp` routes** still reads
first. A client that speaks within **500 ms** is routed by what it says,
exactly as before. A client that has said nothing after 500 ms is raced
against the `tcp` route's backend: the gateway connects to the backend and
keeps listening to the client. If the backend speaks first, it is a
server-first protocol and gets the session, greeting and all. If the client
speaks first -- a browser that opened the connection before it had a request,
a request whose first packet was lost and resent -- it is routed by what it
said, and the backend connection is closed having received nothing. If neither
speaks within the entrypoint's read timeout (15 s unless set), both are
closed; if the backend cannot be reached, the client is closed at once.

The 500 ms is measured, not chosen: a client that speaks first sends its
opening bytes right after connecting at any round-trip time, and later only
behind a slow uplink (~210 ms for a full packet at 64 kbit/s) or when that
packet is lost and resent (~300 ms later at 50 ms RTT). There is no setting.

**Who is affected:** plaintext TCP entrypoints with a `tcp` route.

What an operator should do (`doc/email-backend-setup.md` gives the same rules for mail):

1. **Give every server-first protocol an entrypoint of its own, with only its
   `tcp` route** -- one entrypoint per port (25, 587, 110, 143, 21, 3306 ...).
   Its greeting then arrives at once.
2. **An entrypoint counts as tcp-only only if no HTTP-type route is served
   there.** A route of type `http`, `grpc` or `graphql` that lists **no**
   entrypoints is served on **every** entrypoint -- including your SMTP port --
   and turns every entrypoint into a mixed one, with the 500 ms greeting delay
   below. List entrypoints explicitly on HTTP routes. An `ssh` or `rdp` route
   listing the entrypoint also makes it mixed; a `udp` route does not.
3. **On a mixed entrypoint, a server-first greeting takes 500 ms.** The session
   still works; only the greeting waits. And a client that speaks first (HTTP,
   SSH, RDP) but more than 500 ms after connecting -- a slow or lossy link --
   loses the race to a server-first backend and reaches it instead of its own
   route. Against a backend that waits for its client (TLS passthrough,
   PostgreSQL, Redis), a late client is never misrouted.
4. **TLS-terminating TCP entrypoints** (SMTPS 465, IMAPS 993, POP3S 995 with TLS
   enabled on the entrypoint) never inspected and were never affected: no
   delay. Their backends receive plaintext -- point them at the backend's
   plaintext ports.
5. **An entrypoint with no `tcp` route** behaves as before: a client has a
   second to say something, then is told there is no route (below).

### A TCP entrypoint holds at most max_connections at once — a new default cap

An entrypoint's `max_connections` was stored and read by nothing, so a TCP
entrypoint had no connection limit: a flood of connections, which cost the
client one packet each, cost the gateway two goroutines and several
descriptors each without bound. A TCP entrypoint (plaintext or TLS) now holds
at most `max_connections` connections at once -- L4 sessions and connections
still being inspected; a connection past the limit is closed as soon as it is
accepted. With `max_connections` at 0 (the default, and what every existing
entrypoint has) the limit is the resource profile's: **1000** (`minimal`),
**10000** (`standard`), **50000** (`enterprise`), selected by `GATEON_PROFILE`
as for every other profile default. Refusals are counted with the other
connection-limit rejections on the Diagnostics limit card, and logged at WARN
at most once a minute per entrypoint (`TCP entrypoint at its connection
limit, refusing new connections`). The limit is read when the entrypoint
starts.

**Who is affected:** a TCP entrypoint that holds more concurrent connections
than its profile's default -- more than 10000 on the standard profile. Set
`max_connections` on it (dashboard, config file or API). HTTP entrypoints read
it too now: see "Every HTTP entrypoint holds at most max_connections at once"
above.

### The PROXY protocol header names the address the client connected to

With **Send PROXY protocol** on a TCP service, the header's destination address
and port were the backend's own, not the gateway address the client connected
to, and came from a different socket than the source -- an IPv6 client behind
an IPv4 backend got a header naming one of each, which PROXY readers reject.
The destination is now the address and port the client connected to, as the
PROXY protocol specifies.

**Who is affected:** backends reading the PROXY header's destination -- a mail
server or proxy that tells apart which gateway address or port a client used,
or logs it. The source (the client) was always right.

### A connection a TCP entrypoint has no route for is told so

A connection nothing claims -- a client that says nothing to an entrypoint
without a `tcp` route, or a protocol with no route -- is answered with one line
and closed. The line was `Gateon TCP Entrypoint - <time>`, which said nothing
about why the connection was ending, and whose time ended in the process's
monotonic clock reading (`m=+12345.678`), i.e. its uptime. It is now:

    Gateon TCP Entrypoint - no route for this connection

The same line answers a TLS-terminating TCP entrypoint that has no route. On a
plaintext entrypoint without a `tcp` route a silent client still has a full
second to speak before it gets it, as before. The DEBUG line
`TCP inspection fallback to generic TCP` -- there was never a generic fallback --
is now `TCP inspection: no route for this connection, closing it`, with the
protocol, the byte count (0 for a client that said nothing) and the client
address. The race and the tcp-only path log their outcome at DEBUG
(`TCP inspection: backend spoke first, proxying`, `... client spoke first,
routing by its bytes`, `... the tcp route is all this entrypoint serves,
proxying`). Nothing new is logged at INFO.

**Who is affected:** anyone matching the old banner text or the old DEBUG line.

### First-run setup requires a setup token — **scripted setup must send it**

Setup runs before any account exists, and it required nothing: whoever reached
a fresh gateway first could make themselves its administrator, or use the
wizard's connection test to open a database connection to any address. Setup
and the connection test now require a one-time token. At startup a gateway that
needs setup prints the token in its log and writes it to `setup-token` in its
data directory; the wizard asks for it on its first page, and the file is
deleted once setup completes. See ADR 0021.

**Who is affected:** anything that sets a gateway up without the dashboard --
`POST /v1/setup`, or the `Setup` RPC over Connect or gRPC. Send the token as
`setup_token` (`setupToken` in JSON): read it from `setup-token`, or set
`GATEON_SETUP_TOKEN` (16 characters or more) on the gateway and send that. A
request without it is refused with a message saying where to find it. Gateways
that are already set up are unaffected.

### The setup wizard accepts a SQLite file in a data directory reached through a symlink

The wizard only takes a SQLite database inside the data directory, and it
compared the two paths as written. A relative path is resolved against the
working directory, which the operating system reports with its symlinks
resolved, so a data directory reached through one -- `/var/lib/gateon` linked
to a data disk, or anything under macOS's `/var` -- refused every relative
path, the wizard's default `gateon.db` included. Paths are now compared where
they actually are. A path that leaves the data directory through a symlink
inside it, which the written path hid, is now refused.

**Who is affected:** an install whose data directory is a symlink or sits below
one, which can now use the wizard's SQLite defaults.

### The setup wizard's connection test no longer says why an address that is not Postgres failed

Until setup completes, anyone who can reach the management port can use the
wizard's "Test connection", and Setup itself, to make the gateway connect to an
address of their choosing. Both answered with the driver's error, which told a
refused port from one that answered and hung up, and both from one that never
answered: a port scanner for the gateway's network, open until the first
administrator existed. They now pass on only what a Postgres server said (a
wrong password, a missing database, a host it refuses), answer everything else
with one message after the same five seconds, and log the detail. The attempt
is bounded at five seconds whatever the url asks for; it used to wait as long as
the far end did.

**Who is affected:** an operator whose connection test fails for any reason
other than Postgres refusing it. The reason is in the gateway's log, under
"database connection test failed", rather than in the wizard.

### Required 2FA enrollment shows its QR code and recovery codes — **accounts that enrolled that way never saw theirs**

When an administrator required 2FA, the login page enrolled the account through
`POST /v1/auth/2fa/enroll`, which answered `qr_code_url` and `recovery_codes`
while the page reads `qrCodeUrl` and `recoveryCodes`. The QR image was blank
and the recovery codes were never displayed, so enrollment went through on the
secret typed in by hand. The endpoint now answers in the page's spelling.

**Who is affected:** every account that enrolled through a required-2FA login
from v2.4.2 on. Its recovery codes exist and nobody has seen them. Each such
user can get a new set by setting 2FA up again from their own row in Users
("Manage your two-factor authentication"). Anything outside the dashboard that
reads the two old keys from this endpoint must switch to the new ones.

### eBPF filters IPv6 — **an IPv4-only kernel allowlist now closes the management port to IPv6**

Both eBPF programs passed every IPv6 packet: no shun, no rate limit, no SYN
guard, and no management gate, so with the kernel allowlist on an IPv6 address
reached the management port past it. IPv6 now gets all four. Blocking and rate
limiting are keyed by the /64, because an IPv6 client can send from any address
in its /64; shunning one address shuns its /64. See ADR 0020.

**Who is affected:**

- An install with `enable_mgmt_whitelist` on whose list holds only IPv4
  addresses. IPv6 can no longer reach the management port, as the setting
  always claimed. **If you reach the dashboard over IPv6, add that address to
  `mgmt_whitelist_ips` before upgrading**, which now takes IPv6 addresses.
- While the allowlist or port knocking is on, an IPv6 packet from an unlisted
  source whose extension headers the parser does not walk (a routing header,
  destination options, IPsec) is dropped, since it might be addressed to the
  management port. MLD and neighbour discovery are never dropped.
- A dual-stack install with eBPF on: IPv6 traffic now pays the program's cost
  per packet, and an IPv6 source can be shunned and rate limited.

### The packaged service runs as the `gateon` account, not root — **check files it reads outside `/etc/gateon`**

The .deb, the .rpm and `gateon install` ran the gateway as root. The unit now
runs it as a `gateon` system account holding only CAP_NET_BIND_SERVICE, CAP_BPF
and CAP_NET_ADMIN, and the postinstall creates the account and gives it
`/etc/gateon` and `/var/lib/gateon`. See ADR 0019.

**Who is affected:** an install that reads a file outside those two directories
that only root can read — most often a certbot private key,
`/etc/letsencrypt/archive/*/privkey*.pem`, which is 0600 root. A route using it
fails its TLS load with "permission denied". Give the `gateon` group read
access, or deploy the certificates into `/etc/gateon`. To stay on root, run
`systemctl edit gateon` and add `User=root` and `Group=root` under `[Service]`.

### `GET /v1/system/interfaces` reports `ebpf.attachMode` and `ebpf.loadError`

They were `attach_mode` and `load_error`, which the dashboard's eBPF card never
read: an attached program always showed as "XDP attached (native mode)", and a
failed attach never showed its reason. On a NIC that falls back to the TC hook
the card now says so, including that port knocking, phantom ports and load
balancing are not in force there.

**Who is affected:** anything outside the dashboard that reads the two old keys
from this endpoint. `GET /v1/security/posture` already used `attachMode`.

### "Update now" in the GeoIP settings uses the licence key in the form

The GeoIP card sends the licence key it shows, so a key can be tried before it
is saved, and `POST /v1/geoip/update` read it under a name the card does not
use. The update ran with the saved key instead, and with none saved it answered
"maxmind license key not configured" to an operator looking at the key they had
just entered. It now uses the key sent, and the saved one only when none is.

**Who is affected:** anyone who pressed "Update now" with a key in the form
that was not the saved one: the download used the saved key.

### The setup wizard's database step takes effect — **a wizard-built install may be on `gateon.db`**

The first-run wizard's "Test connection" button answered `400 missing database
configuration` whatever was filled in, and finishing the wizard saved neither
the management database nor the dedicated logging database it asked for: the
administrator was created in `gateon.db` and the gateway ran there. The
dashboard sends protojson's lowerCamel (`databaseConfig`, `sqlitePath`), which
the connection test and the REST setup handler read through snake_case tags,
and it submits setup over Connect, where the database fields were never read.
Both now work, and setup saves the databases before it creates the
administrator, so the account is created in the database that was chosen.

**Who is affected:** an install set up with the wizard from v2.4.2 on that
chose PostgreSQL, a connection string, a SQLite path other than `gateon.db`, or
a separate logging database. It is running on `gateon.db` in its data
directory, with its logs in the same file, and `global.json` names no database.
Nothing moves on upgrade. The database it asked for, if it was created at all,
is empty: pointing `auth.database_url` at it reopens first-run setup, because it
holds no administrator, until setup is run again against it.

### eBPF starts for a process holding CAP_BPF and CAP_NET_ADMIN, whatever its uid

eBPF used to start only for uid 0, while the error it logged said the
capabilities would do. It now asks for exactly those: CAP_BPF and CAP_NET_ADMIN,
or CAP_SYS_ADMIN. CAP_PERFMON is not needed. See ADR 0018.

**Who is affected:** a service run as its own user with the capabilities, which
was refused and now starts eBPF; and root with the capabilities dropped, which
was let through to fail at load and is now refused with the missing ones named.
The packaged systemd unit runs as root and is unaffected. In a container, run
eBPF as uid 0 with the rest dropped — `--user 0 --cap-drop ALL --cap-add BPF
--cap-add NET_ADMIN`, plus `--network host` to filter on the host's NIC —
because a container gives added capabilities to no other user.

### The Helm chart's eBPF mode runs the container as uid 0 — **it never started eBPF before**

`ebpf.enabled` granted NET_ADMIN and BPF to a container running as uid 65532,
which could not use them, so eBPF never started. It now runs the container as
uid 0 with every other capability dropped, escalation blocked and the root
filesystem read-only. The new `ebpf.hostNetwork` (default off) attaches to the
node's NIC instead of the pod's interface.

**Who is affected:** a release with `ebpf.enabled: true`. Its pod now runs as
uid 0, and eBPF starts once it is on in gateon's settings.

### eBPF attaches at the TC hook when native XDP is refused — **it now filters where it did nothing**

With eBPF on and an XDP feature on (`xdp_ip_shunning`, `xdp_rate_limit`), a
NIC that refused native XDP ended up with nothing attached unless
`tc_filtering` was also set — and every EC2 instance refuses it at its
defaults. The gateway now falls back to the TC ingress hook on its own and
enforces there what was configured: shunned addresses, the rate limiter if it
is on, the management allowlist if it is on. See ADR 0017.

**Who is affected:** an install with eBPF on, on a NIC without native XDP — on
EC2, all of them. Its eBPF counters read zero; they now move, and every packet
pays the TC program's cost. To keep the old behaviour, turn eBPF off. Generic
XDP stays opt-in (`allow_generic_xdp`) and is slower than TC.

### A NIC without native XDP no longer runs generic XDP labelled "native"

The native attach passed no mode flag, and with none the kernel attaches in
generic (SKB) mode whenever the driver has no native XDP — e1000, r8169,
bridges — which the gateway and the dashboard reported as native. The attach
now asks for driver mode by name, is refused on such a NIC, and falls back to
TC as above. ENA was never affected.

**Who is affected:** an install with eBPF on, on such a NIC. Its attach moves
from generic XDP, mislabelled, to TC, which is cheaper.

### With no interface set, eBPF attaches to the default-route interface

`ebpf.interface` defaulted to `eth0`, which no current EC2 host has, so an
unconfigured install there failed with "no such network interface". Empty now
means the interface carrying the IPv4 default route: `ens5` on an EC2 host,
still `eth0` inside a container. A configured interface is used as before.

**Who is affected:** an install with eBPF on and no interface set, on a host
whose default route is not on `eth0`. It now attaches where it did not.

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

### Client addresses are no longer sent to ip-api.com — **without a GeoIP database, findings have no location**

With no local MaxMind database -- the default, since the database needs a
licence key -- every client address the anomaly analysis looked up was sent in
plaintext to `http://ip-api.com`, one request a second on the analysis path.
Client addresses are personal data, and nobody configured that service. Geo
lookups are now local only: without a database a finding's location is unknown,
and the dashboard's map says so and where locations come from.

**Who is affected:** installs without a GeoLite2 database, whose map showed
locations from ip-api.com. Add a MaxMind licence key (Settings → GeoIP, or
`geoip.maxmind_license_key`) to get them back from a local database.

### Automatic kernel rate limits lapse five minutes after they were last set — **they never lapsed**

With eBPF on, the WAF (a request scoring 10 or more), the HTTP rate limiter (a
rejected request), anomaly detection, the diagnostics loop's automatic
mitigation and the reinforcement-learning limiter each throttled a source in the
kernel. Only the last ever lifted a throttle, and only its own, so the others
lasted until the process restarted or eBPF was reconfigured. (The automatic
mitigation's immediate throttle is gone altogether; see "AI findings rate-limit
an address only after they repeat".) One WAF hit from an
office's shared address held everyone behind it to a packet a second, and once
the kernel map filled, no new throttle could be installed at all.

Every such throttle is now a five-minute lease. A writer whose reason persists
sets it again and keeps it; one whose reason has passed lets it lapse, and it is
lifted within half a minute of lapsing. IPv6 throttles are leased per /64, as
the kernel applies them. Shunned addresses and the management allowlist are not
affected.

**Who is affected:** installs with eBPF enabled. A source stops being throttled
about five minutes after it stops misbehaving, where before it stayed throttled
until a restart.

### Under sustained memory pressure the proxy cache is purged once a minute, not every five seconds

Above 80% memory use the resource governor purges the proxy cache, which drops
every route's balancer and backend connection pool. It did so on every
five-second sample for as long as the pressure lasted, so every request after
each purge opened new backend connections -- twelve times a minute, on a host
already short of memory. It now purges when pressure begins and at most once a
minute while it lasts; a new spell of pressure still purges at once. The
"high memory pressure detected" warning follows the purges.

### `ai_predictive` load balancing balances — **it sent every request to the first target**

The `ai_predictive` policy (also spelled `intelligent`) sent every request to
the first target in the service and never tried the others. It assumed half a
second for a backend it had not measured, broke every tie in favour of the first
target, and ranked backends by the traffic predictor's spike score, which is 0
for any backend whose latency is steady -- so a backend answering in 500 ms
every time beat one answering in 5 ms.

It now routes each request to the target with the lowest predicted latency
times one more than its requests in flight. A target not yet measured is priced
like the best measured one, so every target is tried; the estimate of a target
that gets no traffic decays by half every ten seconds, so a backend that was
slow once is retried; and a latency spike, as the predictor sees it, weighs up
to double. Before any target has been measured it behaves as least-connections.

**Who is affected:** any service using `ai_predictive` or `intelligent`. Its
other targets start receiving traffic. The policy costs about 0.3 µs more per
request than before, because it now prices every target instead of only the
first, and no longer allocates.

### A custom `--ai-model` must be a WASI reactor — **a model built as a command never predicted**

`make models`, and so anyone following it, built the WASM traffic model as a
WASI command. A command's `_start` runs `main` and exits when it returns, taking
the module with it: the model loaded without error, the log said it was
initialised, and every prediction failed, so the balancer silently used its own
average instead. The gateway now runs a model's `_initialize`, asks it for one
prediction at startup, and refuses a model that cannot answer, saying why.

**Who is affected:** anyone passing `--ai-model`. Rebuild the model as a reactor:
`GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared`. A model that still
cannot answer is logged as not installed and the predictor stays off, rather
than being reported as running. Without `--ai-model` nothing changes.

### Setting up 2FA for your own account asks for your current password

Self-service 2FA setup (`POST /v1/auth/2fa/setup`, the "Enable 2FA" dialog on the Profile and Users
pages) used to need only a signed-in session. In the dashboard that session is an HttpOnly cookie
that script in the page can ride without reading, and setup hands back the TOTP secret -- so a
stored-XSS payload could enrol the account with a secret it held, and on an account that already
had 2FA, replace the owner's authenticator. Setup now requires the account's current password
(`password` in the request body). A missing password is refused with 400; a wrong one with 403,
and it counts towards the same lockout as a failed sign-in (five failures lock the account for
fifteen minutes, for sign-in and setup alike), after which setup answers 429. Nothing is
generated or changed when setup is refused. Enrolment an administrator mandated at sign-in
(`POST /v1/auth/2fa/enroll`) already asked for the password and is unchanged.

A wrong code while a signed-in user completes their own enrolment (`POST /v1/auth/2fa/verify`
with a session) is now answered with 403 instead of 401. The dashboard reads any 401 as an
expired session, so a mistyped code used to sign the user out. During sign-in, when there is no
session yet, a wrong code is still 401.

**Who is affected:** scripts that enable 2FA for their own account through the API must send the
account's password with the setup request, and should treat 403 on a signed-in verify as a
wrong code. Dashboard users are asked for their password in the dialog.

### Changing your own password asks for your current password — **API clients changing their own password must send it**

Changing your own password needed only the session -- over REST (`POST /v1/users/password`) and
the `ChangePassword` RPC alike -- and in the dashboard the session is an HttpOnly cookie that
script in the page can use without reading it. A stored-XSS payload could set a password of its
choosing, one that outlives the session it was set from. It now also takes the current password,
under the same rules as sign-in: a missing one is refused as a bad request, a wrong one is refused
with 403 and counts towards the lockout, a locked account gets 429, and nothing changes. Editing
your own account through `UpdateUser` can no longer set its password. An administrator resetting
another account's password keeps today's rule. A successful change ends every session the account
has, this one included, so the dashboard sends you to sign in again.

**Who is affected:** anything that changes its own account's password through the API: send
`current_password` (`currentPassword` in JSON).

### A browser's sign-in answer no longer carries the session token

`POST /v1/login` and the sign-in step of `POST /v1/auth/2fa/verify` set the HttpOnly
`gateon_session` cookie and also returned the same token in the JSON body. A browser -- any request
carrying the `Sec-Fetch-Mode` header, which browsers always send and page script can neither set
nor remove -- now gets the cookie alone; the body's `token` is empty. Clients that are not
browsers send no such header and still receive the token in the body, as before. The
Connect/gRPC `Login` RPC is unchanged.

**Who is affected:** only browser-side code that read `token` from the sign-in response instead
of relying on the cookie; the dashboard never did. API clients, CLI tools and scripts
(curl, Go, Python) are unaffected.

### "Apply automatic fix" on an unlisted route creates a paused route

The Security Hub's "Apply automatic fix" on an `unlisted_route` finding answered "Recommendation
applied" and changed nothing; it was even handed the client's address where it needed the path.
It now creates a route for the finding: rule `` Path(`<path>`) `` -- the exact path, nothing
under it -- named `unlisted <path>`, on the entrypoint the request arrived at, pointed at the
service that already serves that request's host there, or failing that the entrypoint, when one
service does; otherwise at the service most of those routes use. The route is created **paused**
(`disabled: true`), so nothing is exposed until an operator has reviewed it and enabled it in
Routes. When the request named a host, the rule adds `Host()` for it (lower case, without its
port) and the name carries the host, so the same path on two sites gets two routes. The route
carries the middlewares every route pointing at the chosen service shares, in their order; when
those routes disagree it carries none, and the answer says to review them before enabling; the answer names the route, its rule, its entrypoint, its service and
why that service. It is refused, and nothing is created, when the path is already routed, when a
route for it already exists (applying the same finding twice says so), when the path cannot be
written as a rule or is a scanner trap such as `/.env`, when the entrypoint is gone or carries
TCP/UDP, when no service is routed there, or when the caller's role may not change routes --
the fix now needs the Routes permission as well as the diagnostics one. `honeypot_triggered` and
scanner findings never create routes.

`ApplyRecommendationRequest` has three new fields -- `request_uri`, `entrypoint`, `host` -- and
findings (`Anomaly`) carry `entrypoint` and `host`; the dashboard sends them back. A request
without `request_uri`, which is what the dashboard used to send, is refused with a message
saying so. Stored request traces gain a `host` field; traces written before the upgrade decode
without it.
The detector now reports an unlisted path once per analysis pass, with how many requests it
stands for (`Anomaly.occurrences`), instead of once per request.

**Who is affected:** operators who used the button (it now does what it says), and anything
calling `ApplyRecommendation` with `unlisted_route`, which must now send the finding's
`request_uri` and `entrypoint`.

### "Apply automatic fix" is offered only where there is a fix

The button was offered on every finding, and for nine types the engine emits --
`honeypot_triggered`, `honeypot_hit`, `neural_sentinel`, `graph_coordinated_fp`,
`reputation_hit`, `suspicious_activity`, `coordinated_attack`, `system_integrity_violation` and
`configuration_recommendation` -- the click could only answer "not implemented". It is now shown
only for the types `ApplyRecommendation` acts on; the API's answer for the others is unchanged.
The audit entry for an applied recommendation now records what happened (success or not, and
the message) instead of "Applied resolution" before anything ran.

**Who is affected:** dashboard users, who no longer see a button that cannot work.

### `gateon top` signs in, and shows per-route numbers

`gateon top` polled `/v1/status` with no credentials, so with authentication on every poll was
refused and the table stayed empty without an error; with authentication off it was empty anyway,
since `/v1/status` has no per-route numbers. It now reads `GET /v1/routes/stats` and sends a Bearer
token given with `--token` or, to keep it out of the process list, `GATEON_TOKEN` -- the token
`POST /v1/login` returns to an API client. A refused token stops it with a message saying where to
get one.

**Who is affected:** anyone using `gateon top`: pass a token.

### The honeypot bans an IPv6 client's /64, not its address — **one ban now covers the whole /64**

A honeypot ban and the strikes that escalate it were keyed by the exact client
address. An IPv6 customer is delegated a /64 -- 2^64 addresses it can send from --
so a scanner rotating through its own /64 was never refused for more than the one
request that tripped each ban and never climbed the 15m / 1h / 6h / 24h ladder.
Ten thousand such hits filled the ban list to its cap, and at the cap no new ban
is recorded, so from then on nobody who reached a trap was banned -- one customer
could switch the honeypot off for everyone. IPv6 bans and strikes are now kept per
/64, the network reputation is already scoped to (ADR 0011); IPv4 bans stay per
address, and a v4-mapped address (`::ffff:203.0.113.5`) is banned as its IPv4
address. "Remove Mitigation / Allow IP" on any address of a banned /64 lifts the
ban on the whole /64. An address in `GATEON_MITIGATION_ALLOWLIST` is not refused
by a ban its /64 earned through a neighbour.

**Who is affected:** IPv6 clients. A trap hit from one address now refuses every
address in the same /64 for the length of the ban, and repeat hits from anywhere
in the /64 climb the ladder together. That is normally one subscriber (a
household, a phone, a VM); on a hosting provider that puts several customers in
one /64, or behind a 4-to-6 translator (SIIT/NAT46) that presents every IPv4
client inside one IPv6 prefix, one client's trap hit refuses the others too, for
as long as its ban lasts. A holder of a larger block (a /48 has 65,536 /64s) can
still fill the ban list by rotating across /64s.

### A trap path loaded by another site's page no longer bans the visitor

Any web page can make its visitors' browsers request a trap path -- an
`<img src="https://your-gateway/.env">` in a forum post is enough -- and the
honeypot treated that request as a scanner's: one page view banned the visitor's
address, a page left open walked it up to a day, and behind CGNAT or an office
egress it took everyone sharing the address. The recorded threat also carried a
reputation penalty and counted toward blocking the visitor's browser fingerprint,
so two such images took the visitor's reputation to zero and three had their
fingerprint refused on every route, even had the ban itself been skipped.

A trap hit that is a cross-site no-cors subresource load -- `Sec-Fetch-Site:
cross-site`, `Sec-Fetch-Mode: no-cors` and `Sec-Fetch-Dest` one of `image`,
`script`, `style`, `font`, `audio`, `video`, `track`, `embed` or `object` -- is
still refused with 403 and still recorded as a `honeypot_triggered` threat (its
details say "not held against the source"), but adds no strike and no ban, costs
the source no reputation, does not count toward a fingerprint block, and is not
fed to the correlation engine. Every other trap hit is banned as before,
including navigations, iframes and a script's own `fetch()`.

Those headers are written by the client. A scanner forging those headers gains
only a missing ban -- its request is still refused and recorded. The ban it
misses is everything that would outlive the request: the honeypot's ban, the
reputation penalty and the fingerprint escalation.

The honeypot's log line and threat details now say what happened to the source --
"banned 203.0.113.5 for 15m0s", "banned 2001:0db8:0001:0002:: for 1h0m0s" (an
IPv6 /64), "source not banned (loopback, allowlisted, or the ban list is full)"
-- where they said "IP blocked for 24h" whatever happened.

**Who is affected:** sites whose trap paths are linked from other sites' pages.
Their visitors are no longer refused afterwards, and the threat list shows those
loads with the third-party page as the Referer in the request headers. A page
that uses a script's `fetch(url, {mode: "no-cors"})`, an iframe or a link to a
trap path still gets its visitors banned: those are not covered.

### A reputation block follows a client whatever headers it sends — **scores start clean once, and identities look different**

A reputation score was kept for the client's whole JA4+ fingerprint on its
network (ADR 0011), and half of JA4+ is written from each request: the method,
and whether a `Cookie` and a `Referer` were sent. A client the reputation blocker
refused got a fresh, neutral score by dropping its `Referer`, sending a cookie,
or switching from GET to POST. A score is now kept for the part of the
fingerprint a client cannot vary from one request to the next: with TLS, the
JA4 alone; without it (plaintext, or TLS terminated in front of the gateway by a
proxy that does not forward a fingerprint), the JA4H with the method, cookie
and referer marked out -- `_--11--0200_7e33b58890ac`. The same identity drives
proof-of-work difficulty, deception's troll response, the tarpit, the adaptive
rate limits and the rate limiter's `fingerprint` and `ja4h` strategies.
Releasing a fingerprint from the dashboard resets the score of every variant of
it. A client that controls its own TLS stack can still get a fresh score for
each distinct ClientHello it offers. See ADR 0024.

**Who is affected:** every install. Scores recorded before the upgrade are
filed under identities nothing reads afterwards, so every client starts from a
clean score once -- as a restart already does, since scores live in memory.
Within one network (/24, /64), clients of the same TLS stack -- or, without TLS,
of the same HTTP shape (version, and which of `User-Agent` and
`Accept-Language` they send) -- now share one score for all their requests,
where before they shared it only for requests whose method, cookie and referer
also matched; behind a TLS-terminating proxy that does not forward a JA4, that
is every browser on the network. The rate limiter's `ja4h` strategy now counts a
client's GET, POST and HEAD in one bucket. The dashboard's reputation list shows
the new identities (`t13d1516h2_8daaf6152771_b0da82dd1658|203.0.113`). In a
mixed-version cluster, scores gossiped by a node not yet upgraded are not
enforced by upgraded nodes until it is upgraded.

### "Inject Invisible Links" off means no trap link in your pages — **pages served with deception on may lose theirs**

With Honey-Potting & Deception on, the honeypot every entrypoint carries
injected its own hidden `/_gateon_trap_<id>` link into every HTML page whatever
the "Inject Invisible Links" switch said, so the switch the dashboard showed off
was not the one in force. The link now follows the switch; the configured
Invisible Link Paths already did. The injected link also carries
`rel="nofollow"`, as the configured links always have, so a search crawler that
reads the markup is asked not to follow it -- one that did was banned. The
settings card no longer recommends trapping `/wp-admin` (the built-in list
dropped it because it bans the first administrator to sign in) and says what a
trap hit does.

**Who is affected:** installs with deception enabled that never turned "Inject
Invisible Links" on -- it is off unless set. Their pages stop carrying the
honeypot's trap link; turn the switch on to keep it.

### An external integration's "Confidence Threshold" takes effect — **with the default 80, answers of 21 to 80 stop counting**

Each IP-reputation integration (AbuseIPDB, VirusTotal, AlienVault) has a
"Confidence Threshold -- Score above which to consider IP malicious", and new
integrations default to 80. Nothing read it: the security threat detector
counted any provider answer above a fixed 20. A provider's answer now counts
only when it is above its integration's threshold; an integration saved with no
threshold (0) keeps the old floor of 20. An answer that counts still adds half
its value to the detector's threat score, as before.

**Who is affected:** installs with an external integration whose threshold is
set -- every one created from the dashboard, at 80 unless changed. Addresses a
provider scores between 21 and 80 no longer raise the detector's threat score,
so fewer of them become anomalies; lower the threshold to count them again. A
threshold below 20 now counts answers the fixed floor ignored.

### The Neural Sentinel reports findings — only for clients that are both unusual and harmful

The Neural Sentinel (an isolation forest over each client's traffic) had never
reported anything: its forest refused to score, its scores ran the other way
from its threshold, and the threshold read the dashboard's 0–1 Sensitivity as
0–100. It now reports a client when the forest isolates it from the rest of the
window's clients (standard isolation score of at least 0.75 − 0.10 ×
Sensitivity: 0.70 at the default 0.5, 0.65 at 1.0) **and** its traffic is
harmful: a scan (10+ failed requests over 10+ paths, at least half its
requests), credential guessing (10+ POSTs refused with 401/403, at least 30% of
its requests), or attacks the WAF, traps or anomaly detection caught (at least
20% of its requests). A CI runner, an office's egress or a status poller is
unusual but not harmful, and is not reported. Sensitivity 0 now turns the
detector off (it used to fall through to a more sensitive setting). It needs at
least 20 clients with five or more traced requests in the window, and it skips
its pass while the resource governor reports CPU pressure instead of running on
a quarter of its trees.

**Who is affected:** installs with anomaly detection enabled. Expect
`neural_sentinel` findings for scanners and credential stuffers; each finding
names why the traffic is harmful and which measures set the client apart.

### Graph Intelligence reports campaigns, not browsers — and no longer needs behavioural fingerprinting

Graph Intelligence reported any five addresses sharing a JA4+ value as a
coordinated botnet. A JA4+ value names a browser class, so five people on one
Chrome build were a "botnet"; it never forgot a link, so visitors days apart
clustered; and its gossip never reached the detector. It now links an address
to its client class only when the address carries attack evidence of its own
from the last 30 minutes (WAF blocks, trap hits, malware uploads, brute-force or
exploit-scan detections — not rate-limit rejections), lets that evidence fade
(10-minute half-life, gone after 30 minutes), and reports a class only when five
or more such addresses are at least half of the addresses that presented it. It
reads the fingerprint recorded on threats, so it works whenever anomaly
detection is on; `enable_behavioral_fingerprinting` is no longer needed for it.
The per-address detector's "Multi-IP attack detected via fingerprinting" finding
is retired: it was the same browser-class mistake, recorded as a threat on every
pass.

**Who is affected:** installs with anomaly detection enabled that saw
`graph_coordinated_fp` or "Multi-IP attack" findings for ordinary visitors: they
stop. Clusters in a gossip cluster: nodes now exchange attack links (type
`attack_evidence`) and ignore the evidence-free `fp_ip` edges older nodes send,
so distributed detection works once every node runs this release.

### AI findings rate-limit an address only after they repeat, and the highest threats get the tightest limit

The analysis loop used to rate-limit, in the kernel, every address a Neural
Sentinel or Graph Intelligence finding scored above 80 — at once, on one
finding, to 100 packets a second. That path is removed. These findings now go
to the reinforcement-learning limiter, which limits an address only after
findings on three consecutive analysis passes (three minutes at the default
interval), renews the limit while the findings continue, and lets it decay and
lapse (five-minute lease) when they stop. The mitigation allowlist
(`GATEON_MITIGATION_ALLOWLIST`) is never limited, and **Allow** on a mitigation
now also clears the limiter's history for the address, so the next pass does not
limit it again. The limiter's table also ran backwards — its most dangerous band
allowed 100 packets a second and its mildest 5 — and now tightens with the
threat: 100, 20, then 5 packets a second (after a 64-packet burst). IPv6 is
tracked per /64, as the kernel limits it.

**Who is affected:** installs running eBPF with anomaly detection enabled. An
address named by a single finding is no longer limited.

### Every kernel rate limit is on the IP Mitigations list

The WAF, the HTTP rate limiter, anomaly detection and the RL limiter all
rate-limit addresses in the kernel, and none of those limits was shown anywhere.
The Security Center's **Mitigated › IP Mitigations** list (and the combined
`mitigated` status of `ListSecurityThreats`) now starts with every limit in
force, typed `kernel_throttle` and marked Throttled, with its rate, the reason
its writer gave and when it lapses; the Mitigated count includes them. **Allow**
on a throttle lifts it at once (for IPv6, its /64).

**Who is affected:** anyone using eBPF. API clients reading the IP or combined
mitigation lists will see the new `kernel_throttle` rows first; their `source`
is the address (or the /64's network address) to release, and the expiry is in
the description.

### The status snapshot says whether the Neural Sentinel and Graph Intelligence run

`neuralSentinelEnabled` and `graphIntelligenceEnabled` in the status snapshot
were always true. They now say whether each detector runs under the current
configuration: the Neural Sentinel when anomaly detection is on at a sensitivity
above zero, Graph Intelligence whenever anomaly detection is on.

**Who is affected:** dashboards and scripts reading those flags: on the default
configuration (anomaly detection off) both now read false.

### The request-timing check no longer reports pollers, and the header-consistency check is gone

The per-address detector's timing check had never had an input: the analysis
read its traces newest first and discarded every gap between requests. With the
gaps measured, the check gave a steady rhythm 60 points on its own — twice the
default threat threshold — which would have reported every dashboard poll,
health check and CI job. A steady rhythm now adds 25 points, and only to
traffic that is already harmful by the rules above. The check that a client
calling itself Mozilla sends Accept-Language was removed: it never saw a header
(the analysis reads trace summaries), reading full traces costs up to a gigabyte
a pass when clients pad their headers, and it misfired on crawlers and
gRPC-Web/Connect browsers. The "Inconsistent HTTP headers" reason no longer
appears.

**Who is affected:** installs with per-address behavioural analysis
(`security_advanced.behavioral.enabled`). Under `GATEON_TRACE_SAMPLE_RATE` above
1, failure rates are now judged against the requests an address really sent
rather than the sample, which keeps every failure and one success in N.

### `GATEON_PHANTOM=1` no longer switches on an io_uring listener — **it was slower on every measurement**

With `GATEON_PHANTOM=1` the management listener and every HTTP entrypoint were
wrapped in an io_uring reactor. Measured on two CPUs against the standard Go
listener, it took 6.7x as long per HTTP round trip (222 µs against 33 µs), 31x
as long per 64-byte L4 echo, moved a tenth of the L4 throughput (247 MiB/s
against 2.4 GiB/s up, 274 MiB/s against 3.6 GiB/s down), and kept 8% of a core
busy with no traffic at all. Shortening its polling tick bought latency with
more idle CPU (15% of a core at 100 µs, 30% at 10 µs) and never caught up. It
also ignored read deadlines, so a `Connection: close` response never ended and
an idle client held its connection forever, and closing it did not stop
`Accept`, so a graceful shutdown hung until the process was killed.

The wrapper is gone and the variable does nothing. If it is set, startup logs
once, at WARN, that it no longer changes anything. `GATEON_XDP_IFACE`, which
switched on an AF_XDP path that created a socket and then failed on every
connection (logging a warning for each one), is retired the same way.

**Who is affected:** installs that set `GATEON_PHANTOM=1` or `GATEON_XDP_IFACE`.
They now run the standard listener every other install runs, which is faster.
Remove the variables to silence the startup notice.

### Plaintext TCP routes splice in the kernel, and a backend that hangs up ends the client's session

A plaintext TCP entrypoint reads each connection's first bytes to tell SSH,
RDP and HTTP apart, and then handed the L4 proxy a wrapper that hid the socket
underneath. So the proxy never used splice(2): every byte went through a
32 KiB user-space buffer each way, and each session allocated two of them.
And it could not half-close the client, so when a backend answered and closed
-- whois, finger, anything that ends a response by closing -- the client was
never told and the session stayed open until the client gave up.

Both now work. On two CPUs an L4 route moves 36% more upload and 77% more
download throughput, uses 28-45% less CPU per MiB, and a session allocates
4.3 KiB instead of 68.4 KiB. Each spliced session holds two kernel pipes
(four descriptors) for its lifetime, where it held two 32 KiB heap buffers, so
an open L4 session now costs six descriptors instead of two. Go raises the soft
descriptor limit to the hard one at start (524288 under the packaged systemd
unit's default); only a host with a low hard `nofile` limit needs to raise it.

**Who is affected:** plaintext TCP entrypoints with an L4 route. Clients now
see the connection close when the backend closes it; before, they waited.
TLS-terminating TCP entrypoints are unchanged (they cannot splice).

### The L4 resolver no longer prints every connection's backend list to stdout

Every connection a TCP entrypoint accepted printed
`L4 Resolver: Service <id> has <n> L4 backends: [...]` to standard output,
outside the logger and regardless of the log level. The line is gone. The
logger now records `L4 backend pool built` (entrypoint, network, backends) at
INFO once when a route's backend pool is built or rebuilt after a
configuration change.

**Who is affected:** anyone who collected or grepped those stdout lines; the
new log line carries the same information once per change.

### The resource governor measures memory pressure against the gateway's own budget — **not the host's RAM**

Above 80% memory use the governor runs its scavengers (the proxy cache purge
among them). "Memory use" was the host's RAM used%, so a gateway in a 512 MiB
container on a large node could reach its OOM line without ever scavenging,
and on a shared host other processes' memory triggered purges of the
gateway's caches.

It now measures against, in order: the Go memory limit when one is set
(`GOMEMLIMIT` or `GATEON_MEMORY_LIMIT`), using the Go runtime's own memory; else
the process's cgroup v2 `memory.max` when it is limited (a container
`--memory`, Kubernetes limits, systemd `MemoryMax=`), using the cgroup's working
set (`memory.current` less reclaimable `inactive_file` page cache); else the
host's RAM, as before. Startup logs `resource governor started` with
`memory_yardstick` naming which, and the high-pressure warning names it too.

**Who is affected:** installs with `GOMEMLIMIT`/`GATEON_MEMORY_LIMIT` set or
running in a memory-limited container or unit. The governor now scavenges
when the gateway nears its own limit, which may be sooner (a busy small
container on an idle host) or later (an idle gateway on a busy shared host)
than before. The Diagnostics card's memory figure is the same percentage.

### The Diagnostics Phantom Core card reports the kernel splice path and its live sessions

The card's engine and badge now describe how proxied bytes actually move: on
Linux, `splice (zero-copy)` with a ZERO-COPY badge, because plaintext TCP
routes are spliced by the kernel; elsewhere `standard` with a STANDARD badge
(it said OPTIMIZED/FALLBACK). Its second line is the number of TCP sessions
being spliced at that moment. In the API (`SystemInfo.titan`), `phantom_engine`
changes accordingly and `active_phantom_ports` now carries that session count;
it was always 0.

**Who is affected:** anyone reading `titan.phantom_engine`,
`titan.phantom_enabled` or `titan.active_phantom_ports` from the diagnostics API.

### TCP entrypoints log each L4 connection at DEBUG, and a client hanging up early is no longer an ERROR

At the default INFO level a plaintext TCP entrypoint logged every L4 session
(`TCP inspection: Route found, proxying`, plus `SSH protocol detected on TCP
entrypoint` or `RDP protocol detected ...`), and a client that disconnected
before sending anything -- every port scan and TCP health probe -- as
`level=ERROR msg="TCP inspection initial read error" error=EOF`. These are now
DEBUG: one `TCP inspection: route found, proxying` line carrying the protocol
and the client address, and `TCP inspection: client left before sending`. At
INFO an L4 connection logs nothing.

**Who is affected:** anyone alerting on or counting those lines. Set the log
level to `debug` to see per-connection routing again; use the Diagnostics
connection counters for volume.

### An entrypoint with SSH and RDP routes keeps each route's backend pool and its health state

A TCP entrypoint's backend pool was cached per entrypoint, so on an entrypoint
with several TCP routes (SSH and RDP, or a protocol route beside a generic one)
each connection that chose a different route than the one before rebuilt the
pool: every backend was marked healthy again, least-connection counts were
reset and the health checks restarted. A backend taken out of rotation by
failed checks returned with the next connection of the other protocol. Pools
are now kept per route, and the `L4 backend pool built` line appears once per
route instead of once per alternation.

**Who is affected:** TCP entrypoints carrying more than one TCP route. Health
checks and `least_conn` now behave as configured.

### TLS-terminated TCP sessions reuse their copy buffers

Sessions through a TCP entrypoint that terminates TLS cannot be spliced; they
were copied through two freshly allocated 32 KiB buffers each. The buffers are
now pooled: a short TLS session allocates 117 KiB instead of 181 KiB (most of
the rest is the TLS handshake), with latency unchanged.

**Who is affected:** TLS-terminating TCP entrypoints; less garbage-collection
pressure under many short sessions. No configuration change.

### The Logs page's route, status and client filters work on the text-format log

The filters on **Logs** read fields from JSON lines only. The gateway writes
slog's text format unless `log.format` is `json` or `ENV=production`, so on those
installs choosing a route, a status or a client address hid every line, and the
route list was empty. On JSON logs the client filter looked for field names the
access log never writes, and the status box's own example, `5xx`, matched
nothing. The page now reads text-format lines too, matches the `client` and
`remote_addr` fields, and treats `4xx`/`5xx` as status classes.

**Who is affected:** operators using the Logs page. Nothing to change; filters
that showed nothing now show the matching lines.

### Path Metrics refreshes while it is open, and reports a failed load

The **Path Metrics** page fetched its table once and waited for updates on the
live metrics stream that the gateway never sends, so it showed the moment it was
opened, and a path served just before could be missing until a reload. The table
now refreshes on the dashboard's refresh interval (Settings → Appearance,
default 10 seconds) while it is on screen, and a failed load shows an error with a
retry instead of "No path metrics collected yet."

**Who is affected:** operators using Path Metrics. While the page is open it
requests `/v1/diag/path-stats` once per refresh interval.

### Routes saved from the dashboard serve plain HTTP again — **re-save routes edited in the dashboard**

The route form sent an empty `tls` section with every route it saved, and the
gateway treats any `tls` section as "HTTPS only": plain-HTTP requests to such a
route are refused with 403 "HTTPS required". Every route created in the
dashboard, and every HTTP route opened and saved there (to rename it, say),
stopped serving plain HTTP. The form now leaves the section out unless the
route has a TLS option, a certificate or ACME.

**Who is affected:** routes created or edited in the dashboard without a TLS
option or certificate. They still carry the empty section, and still refuse
plain HTTP, until they are saved again from the dashboard (or `tls` is removed
from them through the API or `routes.json`).

### Certificates and Client Authorities cannot save over TLS after a failed load

Both pages kept editing an empty placeholder when they could not read the
gateway's configuration, and saving from it turned TLS off and removed every
other certificate or client authority. They now show the load error with a
Retry, and adding is disabled until the configuration has loaded.

**Who is affected:** nobody needs to act. If TLS was switched off unexpectedly
after a certificate change, this was the cause.

### Deleting from the dashboard asks first, naming what is deleted

Routes (from the table), services, entrypoints, certificates and client
authorities were deleted on the first click; TLS options and users asked a
question that did not say which. All of them now open a confirmation that names
the item and its id.

**Who is affected:** dashboard users; scripted clients of the API are not.

### The Users page reports refused changes

Creating, editing, disabling or deleting a user that the gateway refused used to
do nothing visible. It now shows the gateway's message and keeps the form open.

### The Docs page renders its tables, and its guide links open the guide

The guides' tables -- the Introduction's index among them -- showed as raw
`| Document | Description |` text: react-markdown renders GitHub tables only with
the `remark-gfm` plugin, which is now included (it adds about 13 kB gzipped to the
Docs page's own chunk, nothing to the rest of the dashboard). The index's links
pointed at files the gateway does not serve and opened a window reading "Not
Found"; each now opens its guide's tab, and the two guides that had no tab --
Management Entrypoint and WebSockets & SSE -- have one.

**Who is affected:** readers of the Docs page.

### Quick Presets keep the settings they do not name

Applying a preset in Settings replaced the whole logging section (and, for
High-Throughput, the transport section), so saving afterwards reset every
retention period, the trace-archive limits and the transport timeouts to their
defaults. Presets now change only the fields they name.

**Who is affected:** anyone who applied a preset and saved. Check the retention
periods and trace-archive settings if you did.

### The WAF rule editor reports rules the gateway refuses

Saving a rule the gateway rejects (for example a regular expression RE2 cannot
compile) used to show "WAF Rule created successfully" and close the editor,
although nothing was stored. The editor now shows the gateway's reason and stays
open.

**Who is affected:** operators writing custom WAF rules; a rule you believed was
saved may not exist.

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
