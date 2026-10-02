# 40. The security boundary in the global settings needs an administrator

Date: 2026-10-02

## Status

Accepted. Co-signed `arch` ↔ `sec`: it moves a trust boundary. Writing the
global configuration was an operator's; writing the part of it that decides who
reaches and signs in to the management plane, whom the gateway trusts, and what
record is kept of either, is now an administrator's.

## Context

The hardcoded RBAC table gives the operator role write on `global`
(`internal/auth/rbac.go`, `allowedHardcoded`), so the dashboard's Settings page
works for them. Nothing inside the save looked at *which* settings changed, and
the global configuration holds the security boundary itself. The 2026-10-02
review (finding M3, consolidated A2) showed the consequence live:

1. An operator's `PUT /v1/global` with `auth.enabled=false` and
   `management.allowPublicManagement=true` returned 200, effective at once, no
   restart.
2. On a data-plane entrypoint, with no credential, `GET`/`PUT /v1/global`,
   `/v1/routes` and `/v1/audit/logs` answered 200.
3. An anonymous `POST /v1/users/password` reset the administrator's password.

The same write let an operator grant themselves `users:*` through `rbac`,
replace the PASETO session key (every session ends), narrow
`management.allowed_ips` to lock administrators out, and -- finding M8 --
switch audit off. That last change was not recorded: the save was audited
*after* it was applied, by which time audit was off. The log held the
administrator's enable and nothing after it.

`RequirePermission` (REST) and the `apiPermissions` table (Connect/gRPC, ADRs
0006/0027) cannot express this. The permission they enforce is `(write,
global)`, which the operator holds, and neither sees the contents of the save.
This is the shape ADR 0038 met for route bindings: the rule is a property of
*what the save does*, not of the procedure.

Taking `global` write away from operators was considered and rejected. Most of
the global configuration is the operator's job -- WAF tuning, GeoIP, alerting,
retention of traffic data, TLS certificates, the resource profile -- and
operators run it today.

## Decision

**Every field reachable from `GlobalConfig` is classified Boundary
(administrator-only) or Operational. A save by a caller who is not an
administrator is refused when it changes any Boundary field from what is
stored; the refusal names the fields.** An administrator may change everything.

### Where it is enforced

In `ApiService.UpdateGlobalConfig`, the one save REST (`PUT/POST /v1/global`,
`PUT /v1/config`), gRPC and -- should it ever be wired -- Connect funnel
through, and in `ApiService.editGlobal`, which the fixed-purpose internal
writers now use (the AI-advisory recommendations and the ClamAV mode). Code:
`internal/authz/globalbound`, called from `internal/api/global_config.go`.

It runs after the omitted sections are kept and every stored-secret placeholder
is restored (ADR 0028), and before anything takes effect -- before the session
key is rotated, before the store is written. A refusal is `403` over REST and
`PermissionDenied` over gRPC, and changes nothing.

The other writers of the global configuration, and why they are not held to it:

- **Config import** (`POST /v1/config/import`) carries routes, services,
  entrypoints and middlewares. It has no global section, so it is not a way
  around this.
- **Setup** writes `auth` and the management bind/port. It runs only while
  setup is required, before any account exists, behind the setup token (ADR
  0021).
- **GitOps** replaces the whole configuration from a repository on a timer.
  Its source -- `management.gitops` -- is itself Boundary, so only an
  administrator chooses the repository; what it says is that administrator's
  choice.
- **Bootstrap** runs at start-up from the operator's own files.

### Who counts as an administrator

The caller's claims are read the way every other check in `internal/api` reads
them (`callerClaims`). The guard **fails closed**:

- claims present and readable with role `admin` -- administrator;
- claims present but not readable as `*auth.Claims` -- not an administrator;
- **no claims at all** -- an administrator only when authentication is actually
  off (`auth.enabled` false in the stored configuration, or no auth service),
  the condition the management plane authenticates on (`needsAuth`). With
  authentication in force, a save that arrived with no identity is not one an
  administrator made. ADR 0038's guard reads "no claims" as "auth is off";
  this one checks that it is.

### What is Boundary

The table is `internal/authz/globalbound/classes.go`. Boundary, by section:

| Section | Boundary fields | Why |
| :--- | :--- | :--- |
| `auth` | all | sign-in, the PASETO session key (which also encrypts second factors), the user database |
| `rbac` | all | who may do what |
| `audit` | all | whether management activity is recorded, its signing key, its database, its retention |
| `log` | `audit_log_retention_days` | a one-day window deletes the audit trail |
| `management` | all | bind, port, allowed IPs and hosts, CORS, public exposure, the GitOps source |
| `tls` | `client_auth_type`, `client_authorities` | whether client certificates are demanded and which CAs they are trusted from (mTLS) |
| `waf` | `trust_cloudflare_headers` | which header names the client address -- the trust every allowlist and rate limit keys on |
| `waf` | `audit_log_path` | a file the gateway appends request-derived lines to; any writable path |
| `ebpf` | `enabled`, `interface`, `enable_knocking`, `mgmt_port`, `knocking_sequence`, `enable_mgmt_whitelist`, `mgmt_whitelist_ips` | the kernel-side management allowlist and port knocking, and switching off or moving the programs that carry them |
| `redis` | `addr`, `password`, `db` | holds the ACME certificate cache (private keys) and the token revocation store; `enabled` stays operational |
| `debugger` | `enabled` | captures raw request headers and bodies, which carry credentials -- a dashboard session cookie among them when the browser sends it to an app on the same host |

Everything else is Operational: the rest of `tls` (certificates, ACME,
protocol versions), `otel`, the rest of `log`, `transport`, the rest of `waf`,
`ha`, `anomaly_detection`, the eBPF packet filters, `geoip`,
`security_advanced`, `alerting`, `profile`, and the rest of `redis` and
`debugger`.

Third-party credentials in operational sections (the MaxMind key, alerting
tokens, IP-reputation API keys, the bot-management and PoW secrets) stay
operational: an operator configures those integrations, cannot read a stored
one (ADR 0028), and a kept one is bound to its destination (ADR 0028), so
replacing one moves no trust.

### What "changes" means

The dashboard sends the whole object back. A Boundary field is changed only
when its proposed value differs from **both** the stored value and the stored
value as a writer reads it -- a secret configured as a reference
(`$env:NAME`) reads back as the reference and must compare equal when sent back
unchanged. Placeholders are already restored when the guard runs. An absent
section and an empty one are the same: a client sending `"audit": {}` where
none is stored has changed nothing. A message-typed Boundary field is compared
as a whole, so a field added inside it later is administrator-only too.

### Classification is complete by construction

`TestEveryGlobalFieldIsClassified` walks the `GlobalConfig` descriptor and
fails on any field the table does not classify, on a Boundary field inside an
Operational message (whose fields are never compared), and on a table entry no
longer reachable. At run time an unclassified field is enforced as Boundary.
So a field added to the proto cannot default to operator-writable: the build
fails until someone decides, and production refuses operators in the meantime.

### A change to the audit settings is itself audited, first

`UpdateGlobalConfig` writes an audit entry -- `update` on `audit_config`,
naming each changed audit field, with old and new values for booleans and
numbers and only the name for keys and URLs -- **before** the change is stored
or applied, under the audit settings still in force. Switching audit off is
therefore the last thing the log records. If the save then fails, a second
entry says so.

## Consequences

- An operator who needs a boundary setting changed asks an administrator.
  Saving the Settings page with only operational edits keeps working.
- The dashboard shows the boundary settings to operators read-only, with a
  one-line reason, rather than letting a save fail.
- The "disable public management" recommendation is administrator-only for the
  same reason the field is: narrowing exposure can lock out an administrator
  who reaches the dashboard through a public entrypoint.
- The internal writers no longer edit the live configuration in place before
  storing it; the edit applies to a copy, so the comparison can see it and a
  failed save leaves the running gateway untouched.
- The check runs on the management save path only, never on the request path.

### Residue, recorded for a decision

- **Per-route WAF `audit_log_path`.** A route-level WAF middleware can set its
  own `audit_log_path`, and middlewares are operator-writable. The same file
  write is reachable there; it belongs with the middleware-config validation
  (ADR 0043's area), not here.
- **`waf.clamav.docker_image`** is operational: an operator may choose the
  image the gateway runs for ClamAV. It runs unprivileged with only a port
  published, so it is not a host escalation by itself, but it is code the
  gateway starts on the operator's say-so.
- **`log.level`** is operational. Raising it to `error` suppresses the
  security-event lines in the system log; the audit log is the record this ADR
  protects.
- **TLS protocol floor and cipher suites** are operational. The management
  listener is plaintext by default and is not configured from them; on a
  data-plane TLS entrypoint with public management on, a weakened floor needs
  an active network attacker.
- **GitOps content.** An administrator who enables GitOps delegates the whole
  configuration, boundary included, to whoever can push to that repository.
