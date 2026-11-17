# Gateon compromised

What to do when someone else may control your gateway. ADR 0099 explains the
pieces this page relies on. Set them up before you need them (the last
section); most of this page assumes you did.

There are two kinds of takeover, and the second is worse:

- **A dashboard session.** Someone holds an administrator's password and
  second factor, or a live session. They can re-route any route, switch the
  WAF off, publish any internal address the gateway can reach, replace
  certificates, create accounts and lock yours out. They cannot read stored
  secrets back, because the dashboard shows them as stored, and they cannot
  install an unsigned build.
- **The process or the host.** They have all of the above. They also have
  every secret in the gateway's environment (`GATEON_ENCRYPTION_KEY`, the
  session key, `GATEON_AUDIT_SIGNATURE_KEY`, database credentials), every
  private key under `$DATA_DIR/certs/`, and every request in plain text,
  because TLS ends at the gateway.

Backends behind the gateway are only as safe as the checks they make
themselves. Anything they leave to the gateway is gone in a takeover: the WAF,
IP filters, rate limits, and the identity headers an `oidc` middleware sends
(`X-Forwarded-User` is not signed). The same goes for mTLS to the backends,
because the client key is on the gateway.

## 1. How you find out

- **An alert on administrator activity.** With alerting on and at least one
  destination, these go to every destination without a playbook:
  - a password accepted from a network the account has never used
  - a user created, changed or deleted, or a second factor reset
  - audit or alerting settings changed, or the WAF switched off or to
    audit-only (all critical)
  - a WAF rule changed, a certificate or key written, or a ClamAV install
  - a failed audit-chain verification (critical)
- **The off-host audit copy** stops arriving, or disagrees with the dashboard.
  `gateon_audit_forward_connected == 0` for more than a few minutes means the
  copy is not being made.
- **The dashboard's audit log** fails *Verify*, or shows changes nobody on your
  team made.

## 2. Contain

1. If the backends are healthy and the gateway is the problem, send traffic
   around it, through DNS or the load balancer in front, while you work.
   Decide in section 0 of the production runbook whether that path exists.
2. Cut the management plane off from everyone but you. Set
   `GATEON_MANAGEMENT_ALLOWED_IPS` to your own address in the environment file,
   which overrides the stored setting, and restart. Or stop the gateway.
3. Keep the evidence. Copy `$DATA_DIR`, `global.json` and the journal
   (`journalctl -u gateon`) somewhere off the host before you change anything.

## 3. Get back in

**Another administrator account still works.** Sign the compromised account
out (signing out ends every session it has), then change its password and
reset its second factor. Delete every account you do not recognise.

**Every administrator account is lost.** On the host:

```bash
sudo systemctl stop gateon
sudo gateon admin reset <your-username>      # --create if the account was deleted
sudo systemctl start gateon
```

The command prints a new password once. The account becomes an enabled
administrator, its second factor is cleared and owed at the next sign-in, and
every session of every account ends, including the attacker's. It reads
`/etc/default/gateon` for the gateway's environment (`--env-file` to name
another) and refuses unless it runs as root with the gateway stopped. In a
container, run the image as `--user 0` with the data volume and environment
mounted.

**The host itself was compromised.** Do not clean it; rebuild it. Install a
verified release on a new host, restore from a backup taken before the
compromise (backup-restore.md), and then rotate everything in step 4.

## 4. Rotate what was exposed

For a dashboard session, rotate the first two. For the host, rotate all of
them.

| Secret | How |
| :--- | :--- |
| Session key | Replace it in Settings (`auth.paseto_secret`). Every session ends and second factors are re-encrypted under the new key. If `global.json` names its own value, setting `GATEON_SESSION_KEY` does not override it; edit the file. |
| Account passwords and second factors | Every administrator and operator account. |
| TLS private keys | Reissue every certificate under `$DATA_DIR/certs/` and revoke the old ones with the CA. ACME certificates: delete the cache and let them re-issue. |
| `GATEON_AUDIT_SIGNATURE_KEY` | New value in the environment. The off-host copy, verified with the old key, is your record of what came before. |
| Backend credentials the gateway held | Database and Redis passwords, OAuth client secrets, webhook URLs and bot tokens in alerting, IP-reputation API keys, the MaxMind key, middleware secret references. |
| `GATEON_ENCRYPTION_KEY` | Only protects the secrets above while they are on disk. Rotate those secrets; then set a new key on the rebuilt host. |

## 5. Undo what was changed

Compare against your backup and the off-host audit copy:

- Users and roles. Remove any you do not know.
- Routes, services and entrypoints: a changed backend address, a new route to
  an internal address, or an entrypoint you did not create.
- Middlewares: a removed WAF, IP filter, rate limit or auth middleware.
- Global settings: WAF enabled and not audit-only; the management allowlist,
  bind address and public exposure; alerting destinations; audit on and
  signed; trusted proxies and Cloudflare trust.
- Certificates and keys under `$DATA_DIR/certs/`. The audit log has the
  SHA-256 of each upload.
- WAF rules and exceptions.
- The host: a `gateon-clamav` container you did not start, other containers,
  new users, cron entries and systemd units.

## 6. Prepare now

- **Send the audit log off the host.** Set `GATEON_AUDIT_SYSLOG_ADDR`, for
  example `tls://logs.example:6514`, in `/etc/default/gateon`, and
  `GATEON_AUDIT_SYSLOG_CA` if the receiver's CA is private. Each entry carries
  its signature and previous hash. Keep `GATEON_AUDIT_SIGNATURE_KEY` off the
  host too, so you can verify the copy.
- **Turn alerting on** with at least one destination nobody on the gateway
  host can silence, and alert on `gateon_audit_forward_connected == 0` and
  `gateon_audit_forward_dropped_total` rising.
- **Keep audit on and signed** (`audit.enabled`, `audit.sign_entries`).
- **Keep the management plane on loopback** and reach it through a tunnel
  (production runbook, step 1).
- **Keep a backup and the encryption key off the host** (backup-restore.md).
- **Do not let the `gateon` account use docker** unless you run ClamAV in
  docker mode. Membership of the docker group is root on that host. The
  gateway runs ClamAV only from `clamav/clamav`, `clamav/clamav-debian`, or a
  mirror you name in `GATEON_CLAMAV_IMAGE_REPOSITORIES`.
- **Have the backends check for themselves** what they must not lose:
  authentication on their own, network rules that admit only the gateway, and
  no trust in a header they cannot verify.
