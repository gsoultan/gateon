# Upgrading

Changes that alter behaviour on upgrade, newest first. Anything not listed here
is additive or internal.

Where a change can silently disable something that previously worked, gateon
also warns at startup naming the exact setting — you should not have to find it
here after the fact.

---

## Unreleased

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
