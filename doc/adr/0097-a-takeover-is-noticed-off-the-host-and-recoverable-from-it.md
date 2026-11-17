# 97. A takeover is noticed, recorded off the host, and recoverable from it

Date: 2026-11-17

## Status

Accepted.

## Context

We asked what happens when someone takes the gateway over, either with an
administrator's dashboard session or with the process or host itself, and
answered from the code. Five gaps came out of it:

- **Nobody is told.** Alerting read security threats and nothing else. A new
  administrator, a reset second factor, the WAF switched off, audit settings
  changed and a broken audit chain all went to the audit log, and only there.
  That log lives in the database the attacker now holds, and nobody reads it
  until they already suspect something.
- **The record can be rewritten.** The audit log is an HMAC chain. Its key is
  in the same environment as the database, so whoever owns the host can
  rewrite the log and it still verifies. The production runbook told
  operators to "read the audit log from your off-host copy", but the gateway
  had no way to make one.
- **Some changes left no record.** Uploading or pasting a certificate or key
  wrote no audit entry, and an upload with the name of a file in use replaces
  the key a listener serves.
- **A session could run code on the host.** ADR 0090 made the ClamAV image an
  administrator's setting and checked that it was an image. Any image still
  was, so an administrator's session, a stolen one included, could have the
  host `docker run` a container of its choosing.
- **There was no way back in.** An attacker with an administrator's session can
  change every password, re-enrol every second factor and delete every other
  account. The gateway refuses to start on a database with no administrator,
  so emptying the users table does not reopen setup either.

## Decision

**What a takeover does is announced, recorded where the attacker cannot reach,
and undoable from the host.**

1. **Every stored audit entry goes to registered sinks** (`audit.AddSink`), on
   the goroutine that stored it, signed as stored. The Broadcaster drops
   entries for a full subscriber, which suits the live view and does not suit
   an alert or a copy: a flood of system entries would let an attacker choose
   which administrator entry went missing.
2. **Administrator activity alerts** (`alerting.AuditSink`). A password
   accepted from a network the account has never signed in from, a user
   created, changed or deleted, a second factor reset, audit or alerting
   settings changed, the WAF switched off or to audit-only, a WAF rule
   changed, a certificate written, setup, a ClamAV install, an upgrade and a
   failed chain verification all go to every configured destination. They do
   not need a playbook, because an alert that waits for someone to have written
   a playbook is the silence this exists to end. They never block their source,
   because that address is an administrator's. The new-network entry is
   written at the password step, which every transport's sign-in passes. WAF
   and alerting changes get entries of their own, written before the change is
   stored, so switching alerting off is announced to the destinations it is
   being taken from.
3. **A copy of the log leaves the host as it is written**
   (`internal/audit/syslogsink`). `GATEON_AUDIT_SYSLOG_ADDR` names a
   `tls://`, `tcp://` or `udp://` receiver, and `GATEON_AUDIT_SYSLOG_CA` can
   name its CA. Each entry is RFC 5424 syslog, facility *log audit*, whose
   message is the entry as JSON with its signature and previous hash, so the
   copy can be verified against the chain on its own. It is configured from
   the host's environment only, so a dashboard session can neither switch it
   off nor re-point it. Queues are bounded: 1024 account entries, sent first,
   and 2048 system entries, which an attacker can drive at any rate. Details
   are cut at 8 KiB and marked as cut. Drops are counted in
   `gateon_audit_forward_dropped_total{queue}`, and
   `gateon_audit_forward_connected` reports the connection. A failed write is
   sent again on the next connection. An address that is set and cannot be
   used stops the start.
4. **Certificate and key writes are audited**, with the file, whether it
   replaced one, and the SHA-256 of what was written. The hash identifies the
   file without the entry carrying a key (ADR 0060).
5. **ClamAV runs only from a ClamAV repository**: `clamav/clamav`,
   `clamav/clamav-debian`, or one the host adds in
   `GATEON_CLAMAV_IMAGE_REPOSITORIES`. The tag or digest stays the
   administrator's choice. An image already stored is kept at save, so an
   install with a mirror can still change its other settings, and the install
   itself refuses that image until the environment allows it.
6. **`gateon admin reset <username> [--create]`**, run as root while systemd
   says the gateway is stopped, reads the gateway's configuration and
   environment file. It then makes the account an enabled administrator with a
   new random password, clears its second factor so one is owed at the next
   sign-in, and ends every session of every account. The reset is written to
   the audit log. Any SQLite file root touched is handed back to its owner.

Driver: `sec`. Challenger: `arch`. The trust boundary this moves is who may
silence the record and the alarm. A dashboard session no longer can for the
off-host copy, and the alarm about alerting itself goes out before alerting
changes. Getting back into the dashboard now needs root on the host and
nothing else.

## Consequences

- The incident procedure is `doc/incident-compromise.md`, linked from the
  production runbook.
- An install that runs ClamAV from a mirror must add the mirror to
  `GATEON_CLAMAV_IMAGE_REPOSITORIES` before its next install or update.
  `doc/upgrading.md` says so.
- Administrator alerts use the destinations alerting already has. A gateway
  with alerting off sends none, and the startup log does not yet warn about
  that.
- The audit log's chain is still the gateway's own. The off-host copy is what
  makes it trustworthy after a host compromise, and only when one is
  configured.
- `admin reset` works on Linux and macOS. On a host without systemd it cannot
  tell whether the gateway is running and trusts the operator. In a container
  it runs as `--user 0` against the data volume.
- Not done here: a gateway compromised at the process level can still read
  every secret in its environment and every key on its disk. Recovering from
  that means rotating those secrets (see the incident page), which no code
  change removes.
