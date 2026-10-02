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
sudo install -m 0600 /dev/null /etc/gateon.env
sudoedit /etc/gateon.env
```

```sh
# /etc/gateon.env
# 32+ random characters; `openssl rand -base64 48`. Store a copy OFF this host:
# without it, a restored backup cannot decrypt its secrets (backup-restore.md).
GATEON_ENCRYPTION_KEY=...
# Optional: choose the setup token yourself instead of reading it from the log.
# GATEON_SETUP_TOKEN=...
```

```ini
# /etc/systemd/system/gateon.service.d/production.conf
[Service]
EnvironmentFile=/etc/gateon.env
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
governs `/metrics`, so the scraper's address belongs in it.

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

- Use a long, unique administrator password and **enrol 2FA immediately**.
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
2. **Health checks** with both a failure and a recovery threshold, so one bad
   probe does not drain a pool.
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

Scrape `/metrics` on the management entrypoint from an address in its allowlist.
Probe `/healthz` (the process is alive) and `/readyz` (it should receive
traffic; `503` while its telemetry store is not open) on the same port.

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
  - alert: GateonManyShuns
    expr: gateon_active_shunned_entities_total > 500
    for: 10m
```

Also watch, without paging: `gateon_middleware_waf_uninspected_responses_total`
(traffic the WAF could not read, which is not the same as clean traffic), and the
Diagnostics page's connection-limit card for `inflight_rejected` counts climbing
on one entrypoint.

Ship the service's journal and the audit log somewhere off the host. The audit
log is hash-chained, but gateon does not yet offer operators a way to verify
that chain, so the off-host copy is the record to trust after an incident.

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
