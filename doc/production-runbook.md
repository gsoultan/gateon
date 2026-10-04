# Production runbook

This is the order of operations for putting gateon in front of real traffic for
the first time, and for living with it afterwards. It assumes the documented
target: **one node, 2 cores, 2 GB of memory, SQLite or Postgres**, installed
from the release `.deb`/`.rpm` (the tarball and container differ only where
noted). It does not repeat the detailed guides; it says when to use each.

Gateon is young. Every review of it in 2026 found serious defects, and every one
found is fixed and tested, but the rate at which new ones appear has not yet
been shown to fall. So this runbook is built around a **soak**: a period on
traffic you can afford to lose, with a rollback you have already tried, before
gateon becomes the only thing between the internet and something that matters.

## Known issues

A production-readiness review on 2026-10-02 found defects that no setting
avoids. They fall in two groups.

**Fixed after v1.0.0.** Run a release that includes these fixes before putting
gateon in front of internet traffic. On v1.0.0 itself, and only on internal or
already-filtered traffic:

- **Front it.** An anonymous client can switch off per-request timeouts with an
  `Upgrade` or `Accept: text/event-stream` header, and can exhaust a 2 GB host
  with large unterminated headers (fixed: ADR 0042).
- **Create no operator accounts.** An operator can rewrite authentication
  settings in the global configuration and make themselves an administrator
  (fixed: ADR 0040).
- **Do not enrol 2FA.** A 2FA sign-in gets a session no API call accepts, and
  the second step needs no password (fixed: ADR 0039).
- **Serve the dashboard on a hostname no proxied application shares.** The
  admin's session cookie reaches backends on the same host, and the management
  API has no CSRF defence (fixed: ADR 0041).
- **Do not use** basic-auth users without a password, OIDC/JWKS without an
  audience, or rely on a block during a database outage (fixed: ADR 0043; on
  upgrade an OIDC/JWKS middleware without an audience stops serving until you
  set one, see [upgrading.md](upgrading.md)).

**Known limits of the current code.** None of these is a silent no-op any
more -- each is stated where it applies -- but plan around them:

- **Lockout and revocation are per instance.** In an HA pair each node counts
  failed sign-ins on its own, and token revocation needs Redis (a middleware
  with revocation on and no Redis refuses to build). There is no revoke API yet.
- **A target that has just died gets 502s** until its second failed health check
  (up to about 35 s); there is no passive ejection.
- **Existing installs keep their audit setting.** Setup turns audit on for new
  installs; an existing one with audit off logs a warning at start. Turn it on
  and keep the off-host copy section 5 describes.
- **The global WAF's category switches are read-only.** Narrow a category on a
  route WAF; the gateway-wide equivalent needs a configuration change still to
  come.
- **Run one replica.** The Helm chart refuses `replicaCount > 1`: replicas share
  one identity from a Secret, but not their global settings or audit chain yet
  (ADR 0056).
- **The setup wizard's database step can switch a configured database to
  SQLite.** On a gateway whose configuration already names a database (the
  chart's `externalDatabase`), keep the wizard on that database; choosing the
  default SQLite creates the administrator in the existing database and the next
  start refuses to run.
- **Sign-in is budgeted per client, loopback included** (10 a minute by default,
  `GATEON_AUTH_ATTEMPTS_PER_MINUTE`): scripts that sign in in a loop from the
  host share one budget.
- **A challenge raises the cost of automation; it does not prove a human.**
  Clients that cannot run JavaScript are refused on challenged routes, and the
  challenge has no allowlist.

This section shrinks as fixes ship; [upgrading.md](upgrading.md) records each.

## 0. Decide before you install

Write these down. Each later step refers back to them.

| Decision | Recommended default |
| :--- | :--- |
| Soak traffic | One low-risk site or API, or a mirrored copy of real traffic. Not your login, payments or admin surfaces. |
| Soak length | Four weeks: one in staging, one in production with the WAF audit-only, two enforcing. Restart the clock after any critical or high defect. |
| Who is on call | A named person who can roll back without asking anyone. |
| Rollback | The previous binary or package version, kept on the host, plus the database backup from section 7. Rehearse it once (section 9) before the soak starts. |
| Management access | VPN, SSH tunnel or a TLS-terminating proxy. Never the open internet. |
| Database | SQLite for one node. Postgres only if you already run it well. MySQL does not work. |

## 1. Prepare the host before the package

The package's install script **starts the service immediately**, and the
management entrypoint of a fresh install listens on **`0.0.0.0:8080`, plain
HTTP, open to every address** ([management-entrypoint.md](management-entrypoint.md#network-exposure)).
Setup is protected by a one-time token, and everything except setup and health
answers `503` until an administrator exists
([security-posture.md](security-posture.md#before-setup-completes)), but there is
no reason to open the port at all. Put the overrides in place first; the
package's `daemon-reload` picks them up.

```sh
# 1. Secrets, readable by root only. systemd reads this file before dropping
#    to the gateon account, so the account never needs to read it.
sudo install -d -m 0755 /etc/systemd/system/gateon.service.d
sudo install -m 0600 /dev/null /etc/default/gateon
sudoedit /etc/default/gateon
```

```sh
# /etc/default/gateon  (the unit reads it; root-only, never an Environment= line,
# which any local user can read with `systemctl show`)
# 32+ random characters; `openssl rand -base64 48`. Store a copy OFF this host:
# without it, a restored backup cannot decrypt its secrets (backup-restore.md).
GATEON_ENCRYPTION_KEY=...
# Optional: choose the setup token yourself instead of reading it from the log.
# GATEON_SETUP_TOKEN=...
```

```ini
# /etc/systemd/system/gateon.service.d/production.conf
[Service]
# Management on loopback only; reach it through a tunnel or a proxy you run.
Environment=GATEON_MANAGEMENT_BIND=127.0.0.1
Environment=GATEON_MANAGEMENT_ALLOWED_IPS=127.0.0.1,::1
# Sizing for the 2 GB target (deployment-sizing.md).
Environment=GATEON_PROFILE=standard
Environment=GATEON_MEMORY_LIMIT=1536MiB
```

If your scraper or admin network must reach the management port directly, bind
to that interface and list exactly those addresses in
`GATEON_MANAGEMENT_ALLOWED_IPS` instead of using loopback. The allowlist also
governs `/metrics`, so the scraper's address belongs in it. Check the list
before you restart: an entry that is not an address or CIDR is not refused yet,
and a list with only typos locks the dashboard out.

The unit holds only `CAP_NET_BIND_SERVICE`. If you turn on eBPF or HA, link the
shipped drop-in first (`/usr/share/gateon/systemd/ebpf-ha.conf`, see
[upgrading.md](upgrading.md)); without it they refuse to start and say why.

If gateon sits behind a load balancer or Cloudflare, set
`GATEON_TRUSTED_PROXIES` (and `GATEON_TRUST_CLOUDFLARE_HEADERS` for Cloudflare)
to exactly the addresses in front of it, and nothing broader. Every per-client
control, from rate limits to blocks, keys on the address this decides.

## 2. Install and verify the artifact

```sh
VER=1.0.0; ARCH=amd64     # or arm64
gh release download v$VER -R gsoultan/gateon -p "gateon_${VER}_linux_${ARCH}.deb" -p checksums.txt
sha256sum --ignore-missing -c checksums.txt     # must print OK
sudo apt install ./gateon_${VER}_linux_${ARCH}.deb   # or: sudo dnf install ./...rpm
```

Keep the `.deb` and its predecessor on the host; they are the rollback.

Then confirm the posture you asked for is the one you got:

```sh
systemctl status gateon                  # active (running), User=gateon
sudo ss -ltnp | grep gateon              # management on 127.0.0.1:8080 only
journalctl -u gateon | grep -i "reachable from any address"   # must print nothing
journalctl -u gateon | grep -i "encrypt"  # no "too short" / "NOT being encrypted" line
stat -c '%a %U' /etc/gateon /var/lib/gateon   # 750 gateon, 700 gateon
```

## 3. First-run setup

Open a tunnel (`ssh -L 8080:127.0.0.1:8080 host`) and browse to
`http://127.0.0.1:8080`. The wizard asks for the setup token: it is in the log
(`journalctl -u gateon | grep -i "setup token"`) and in
`/var/lib/gateon/setup-token`, which is deleted once setup completes. (If you
set `GATEON_SETUP_TOKEN`, the log names that variable instead of printing it.)

- Use a long, unique administrator password (12 characters at least, which
  the gateway now enforces) and enrol 2FA (on v1.0.0, see Known issues first).
- Create day-to-day accounts as **operator** or **viewer**. Keep administrators
  to the people who would also hold root on the host: an administrator can bind
  credential-carrying middlewares to routes (ADR 0038) and read audit logs.
- Leave authentication on. With it off there is no role separation at all.

## 4. Configure conservatively

Start with what has the shortest distance between configuration and effect, and
the longest test history:

1. **Entrypoints, routes, services, TLS.** Set every timeout explicitly. Leave
   `max_connections` and the per-address cap at their tier defaults unless you
   have measured otherwise (ADRs 0032, 0036). Clients behind one large NAT may
   need `GATEON_ENTRYPOINT_MAX_CONN_PER_ADDR` raised.
2. **Health checks** with an explicit path and both a failure and a recovery
   threshold, so one bad probe does not drain a pool.
3. **Rate limiting** per route, sized from real traffic, not guessed.
4. **The WAF in audit-only**, following [waf-rollout.md](waf-rollout.md) step by
   step. Do not enforce until step 3 of that guide says the cost is acceptable.
5. **Allowlist** your own monitoring, office egress and health checkers in
   `GATEON_MITIGATION_ALLOWLIST`, so an automatic shun can never cut you off from
   your own gateway. Keep it short; an allowlisted source is exempt from every
   block, including the kernel's.

Leave off for the soak anything you have not verified end to end on your own
traffic: in particular the features listed as open owner decisions in the
latest feature-truth review, and anything labelled AI, advisory or anomaly
detection. Turn each on later, one at a time, in audit or report mode first
where it has one.

Middleware secrets are write-only once saved (ADR 0033), and a middleware may
resolve a `$env:`/`$vault:`/`$aws-sm:` reference only if it is listed in
`GATEON_MIDDLEWARE_SECRET_REFS` (ADR 0034). Prefer literal secrets entered once
through the dashboard over references unless you need rotation.

## 5. Monitoring and alerts

`/metrics` is on the management entrypoint, so the scraper's address must be in
the management allowlist, and it needs a credential: an API token with the
`metrics:read` scope. As an administrator, open **API Tokens** in the dashboard,
create a token named after the scraper (one per scraper, so revoking one does not
cut off the others), and copy it when it is shown -- it is shown once and only its
hash is kept. Put it in a file only Prometheus can read:

```sh
install -m 0400 -o prometheus /dev/stdin /etc/prometheus/gateon.token   # paste, then Ctrl-D
```

```yaml
# prometheus.yml
- job_name: gateon
  authorization:
    credentials_file: /etc/prometheus/gateon.token
  static_configs:
    - targets: ["127.0.0.1:8080"]
```

The token reads `/metrics` and nothing else: it is refused on every other path and
is never a dashboard session. It does not expire unless you gave it an expiry;
revoke it under **API Tokens** if the file leaks, and the next scrape is refused --
the `GateonDown` alert below will say so. The dashboard shows when each token was
last used, to the minute.

Probe `/healthz` (the process is alive) and `/readyz` on the same port; neither
needs a credential. `/readyz` answers `503` only when the instance cannot serve:
its telemetry store did not open, or an entrypoint listener did not bind (named
in the body). When it serves but something is failing -- the trace disk is
nearly full, the configuration database does not answer -- it answers `200
ready, degraded: ...`, so a load balancer keeps a working proxy in rotation.
Alert on the degradation through its gauges, below.

Minimum alert set, as Prometheus rules. Tune the thresholds to your baseline
after the first week; these are starting points.

```yaml
groups:
- name: gateon
  rules:
  - alert: GateonDown
    expr: up{job="gateon"} == 0
    for: 2m
  - alert: GateonNotReady          # blackbox probe of /readyz
    expr: probe_success{job="gateon-readyz"} == 0
    for: 5m
  - alert: GateonHigh5xxRate
    expr: |
      sum(rate(gateon_requests_total{status_code=~"5.."}[5m]))
        / sum(rate(gateon_requests_total[5m])) > 0.02
    for: 10m
  - alert: GateonP99Latency
    expr: |
      histogram_quantile(0.99, sum by (le, route)
        (rate(gateon_request_duration_seconds_bucket[5m]))) > 1
    for: 10m
  - alert: GateonBackendDown
    expr: gateon_target_health == 0
    for: 2m
  - alert: GateonCircuitOpen
    expr: gateon_circuit_breaker_state{state="open"} == 1
    for: 1m
  - alert: GateonMemoryNearLimit   # GATEON_MEMORY_LIMIT=1536MiB
    expr: gateon_memory_alloc_bytes > 1.3e9
    for: 15m
  - alert: GateonWAFWouldBlockSpike   # audit-only phase: read before enforcing
    expr: sum(rate(gateon_middleware_waf_would_block_total[15m])) > 0.5
    for: 15m
  - alert: GateonAuthFailureSpike
    expr: sum(rate(gateon_middleware_auth_failures_total[5m])) > 5
    for: 10m
  - alert: GateonConfigDatabaseDown
    expr: gateon_config_db_up == 0
    for: 2m
  - alert: GateonEntrypointNotListening
    expr: gateon_entrypoint_up == 0
    for: 1m
  - alert: GateonTracesDropped
    expr: increase(gateon_trace_dropped_total[15m]) > 0
    for: 15m
```

Also watch, without paging: `gateon_middleware_waf_uninspected_responses_total`
(traffic the WAF could not read, which is not the same as clean traffic), and the
Diagnostics page's connection-limit card for `inflight_rejected` counts climbing
on one entrypoint.

Ship the service's journal and the audit log somewhere off the host. The audit
log is hash-chained and signed; an administrator checks it under **Audit Log >
Verify integrity** (or `GET /v1/audit/verify`, which walks at most 5000 entries
a call and returns a cursor). Verification detects altered or removed entries in
the middle of the chain, but not entries removed from its newest end, so the
off-host copy is still the record to trust after an incident.

## 6. The soak

| Week | Traffic | WAF | Exit criterion to move on |
| :--- | :--- | :--- | :--- |
| 0 | Staging, synthetic and replayed traffic | audit-only | Rollback rehearsed (section 9); every alert fired at least once on purpose |
| 1 | Production, low-risk site | audit-only | waf-rollout.md step 3 cost acceptable; no unexplained 5xx; memory flat |
| 2–3 | Same | enforcing | No critical or high defect; no customer-visible incident attributable to gateon |
| 4 | Widen one surface at a time | enforcing | Same, on the widened surface |

Keep a log of everything surprising, however small. A defect found during the
soak is the soak working; file it, fix or mitigate it, and restart that week.

**Stop and roll back** on any of: a request reaching a backend that a configured
control should have refused; a control refusing traffic it should not and you
cannot narrow it within the hour; memory climbing without levelling off; the
management plane reachable from somewhere it should not be; any loss of
configuration or audit data.

## 7. Backups

Follow [backup-restore.md](backup-restore.md). The short version:

- Back up `/etc/gateon` and the database daily, and before every upgrade.
- **The encryption key is not in the backup.** Keep `GATEON_ENCRYPTION_KEY`
  somewhere that survives the host. Without it a backup restores, but its
  secrets do not.
- Verify a restore onto a scratch host monthly, using that guide's checklist.
  An unverified backup is a hope.

## 8. Upgrades

1. Read every entry in [upgrading.md](upgrading.md) between your version and the
   target. Behaviour changes there are real: defaults move, checks get stricter,
   and some changes need an environment variable set before you start.
2. Back up (section 7).
3. Upgrade staging first; let it run a day.
4. Upgrade production in a quiet hour, with the previous package on the host.
5. Watch section 5's alerts for an hour, and check the dashboard still signs in,
   routes still serve, and a configuration change still appears in the audit
   log.

Never skip straight across several releases in production without having done
the same jump in staging.

## 9. Rollback

Rehearse this once before the soak begins, and time it.

```sh
sudo systemctl stop gateon
sudo apt install --allow-downgrades ./gateon_<previous>_linux_<arch>.deb
# Only if the newer version migrated the database and the old one refuses it:
#   restore the pre-upgrade backup (backup-restore.md), same GATEON_ENCRYPTION_KEY
sudo systemctl start gateon
journalctl -u gateon -n 50
```

If gateon itself is the problem and the backends are healthy, the fastest
rollback may be to send traffic around it (DNS or the load balancer in front)
while you investigate. Decide in section 0 whether that path exists.

## 10. Incidents

- **An address or a whole network is wrongly blocked:** release it in Security
  Center; a release holds for 24 hours. If it is yours, add it to
  `GATEON_MITIGATION_ALLOWLIST`. Automatic shuns lapse on their own (15 minutes,
  doubling on repeats up to 24 hours).
- **Locked out of the management plane:** use the tunnel from the host itself;
  `GATEON_MANAGEMENT_ALLOWED_IPS` from the environment overrides the stored
  config.
- **Suspected compromise of an administrator account:** sign that account out
  (sign-out ends every session of the account), change its password, re-enrol
  2FA, rotate the session key, and read the audit log from your off-host copy.
- **Report a vulnerability** as [SECURITY.md](../SECURITY.md) describes, not in a
  public issue.
