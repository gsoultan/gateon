# Security Posture & File Integrity Monitoring (FIM)

Gateon exposes a consolidated **security posture** endpoint and an opt-in
**File Integrity Monitor** (FIM) that together form the foundation of its
host-detection (Wazuh-like) capabilities.

## Session lifecycle

Dashboard and management-API sessions are PASETO v4 local tokens.

**Lifetime is 8 hours.** A token is a bearer credential, so the window is the
part you cannot revoke by other means — it bounds the damage from a token that
leaks without anyone noticing (a stolen laptop, a copied `curl` command).

**Sessions are bound to the account they were issued for.** Each token carries a
digest of the user's password hash, role and disabled flag. Every authenticated
request recomputes it. Four operations therefore end a user's live sessions on
their *next request*, not whenever the token would have expired:

| Operation | Effect on live sessions |
|-----------|-------------------------|
| Disable a user | Revoked immediately |
| Delete a user | Revoked immediately |
| Change a user's role | Revoked immediately — a demoted admin cannot keep admin claims |
| Change a user's password | Revoked immediately |

Enabling or disabling 2FA does **not** revoke existing sessions; those factors
are checked at login, and a session that already cleared them stays valid. If
you need a user's sessions gone, disable the account or rotate the password.

**A session is not enough to change credentials.** Changing your own password
(`POST /v1/users/password`, or the `ChangePassword` RPC) and starting your own
2FA setup both require your current password, and a wrong one counts towards the
same lockout as a failed sign-in. Editing your own account as a user cannot set
its password. An administrator resetting another account's password still needs
only the administrator role.

**Where the token lives.** In the browser it exists only in the HttpOnly,
`SameSite=Strict` session cookie: `__Host-gateon_session`, Secure, over TLS, and
`gateon_session` on plain HTTP, where a browser refuses the prefix. It is
never written to `localStorage` or `sessionStorage`, and no script on the page
can read it. Sign-in (`POST /v1/login`, and the second step at
`POST /v1/auth/2fa/verify`) answers a browser -- any request carrying the
`Sec-Fetch-Mode` header, which browsers always send and page script can neither
set nor remove -- with the cookie alone; the token appears in the response body
only for API and CLI clients, which send `Authorization: Bearer <token>`. A
query-string token is accepted only on a WebSocket handshake, which cannot set
headers.

**The session stays with the dashboard** (ADR 0041). The proxy removes the
session cookie, and a bearer token the management plane accepts, from every
request it forwards, so no proxied app on the dashboard's host receives it. A
write to the management API -- sign-in and setup included -- and the `/v1/logs`
WebSocket handshake are refused when the browser says another page asked for
them (`Sec-Fetch-Site: same-site` or `cross-site`, or a foreign `Origin`),
unless that origin is configured in `management.cors.allowedOrigins`. API
writes must be JSON (or a Connect/gRPC type; multipart only on the two file
uploads). Management CORS is off unless configured, and every API answer a
cache could keep (GET, HEAD, POST, Connect) carries `Cache-Control: no-store`.

**Multi-instance deployments.** Binding state is cached per process, and a
revocation is propagated to the other instances over the Redis channel that
already carries route, TLS and WAF invalidations. With Redis configured, a
disable takes effect across the deployment in a round trip.

Redis pub/sub is at-most-once, so propagation is an optimisation and never the
guarantee. Cached bindings carry `DefaultBindingTTL` (30s, overridable with
`GATEON_SESSION_BINDING_TTL`) and an expired entry is treated as absent, so a
sibling re-reads the account from the database within that window regardless of
whether it received the message. **With no Redis configured — the default, and
every single-instance deployment — the TTL is the whole mechanism and the
window is up to 30 seconds.**

A message on that channel can only *drop* a cached binding, never create or
change one, so the next verify re-reads the account and the check gets stricter
rather than weaker. See
`doc/adr/0012-session-revocation-propagates-but-expiry-guarantees.md`.

**Rotating the session key.** The key in `auth.paseto_secret` signs every
session and encrypts every stored second factor. Replacing it in Settings, or
through the API, ends every session at once and re-encrypts the second factors
under the new key in the same step, so every enrolment survives. It changes this
instance only.

- **One instance:** replace it in Settings. Nothing else is needed.
- **Several instances sharing one user database:** every instance must hold the
  same key, and until they do, sessions and two-factor sign-ins through the ones
  still on the old key fail. Replace it on one instance, give the others the new
  key -- in their `global.json`, or better in a secret store every instance names
  (`$vault:...`, `$aws-sm:...`, `$env:...`) -- and restart them. The first
  instance has already moved the second factors, so the others find nothing to
  move.
- **A key changed any other way** -- `global.json` edited, the secret a reference
  names rotated at the source -- moves no second factor by itself. At startup
  every instance checks each stored second factor against its key and logs an
  error with the number that do not decrypt: those accounts cannot complete a
  two-factor sign-in. Set `GATEON_PREVIOUS_SESSION_KEY` to the previous key on
  the instances you restart with the new one; the first to start re-encrypts
  those second factors under the new key, and the variable can be removed once it
  has. The previous key only ever decrypts second factors. It never verifies a
  session, so a rotated-away key stays rotated away.

**On upgrade, everyone is logged out once.** Tokens minted before this
mechanism carry no binding and are refused rather than grandfathered in.

## Before setup completes

Until an administrator account exists, the management API serves only the setup
and health endpoints and answers `503` for everything else. This closes the
window in which a freshly installed gateway on a reachable address could be
claimed — or read — by whoever found it first. Completing setup enables
enforcement immediately; no restart is needed.

## File Integrity Monitoring (FIM)

FIM records a cryptographic (SHA-256) baseline of a fixed set of files and/or
directories and periodically rescans them to detect **drift** — files that were
added, modified, or removed since the baseline. This is useful for catching
tampering with served static assets, configuration, or WAF rule sets.

FIM is **disabled by default** and activates only when at least one path is
configured.

### Configuration (environment variables)

| Variable | Description | Default |
|----------|-------------|---------|
| `GATEON_FIM_PATHS` | OS path-list (`:`-separated on Unix, `;` on Windows) of files and/or directories to monitor. Directories are walked recursively; only regular files are hashed (symlinks are skipped). | _unset_ (FIM off) |
| `GATEON_FIM_INTERVAL` | Go duration between scans (e.g. `10m`, `1h`). Values below `10s` are raised to `10s`. | `5m` |

Example:

```sh
export GATEON_FIM_PATHS="/etc/gateon:/var/www/static"
export GATEON_FIM_INTERVAL="10m"
```

When drift is detected, each change is logged as a warning
(`file integrity drift detected`) and counted in the posture report.

## Malicious file signature scanning (YARA-lite)

The `file_security` middleware includes a **dependency-free, pure-Go signature
engine** ("YARA-lite", `internal/security/yara`) that inspects uploaded file
content for malware, webshells, and exploit payloads — without requiring
`libyara`/cgo or any external binary. It complements (and runs before) the
optional ClamAV stream scan and the MIME/magic checks.

A rule is a named set of byte/text `strings` combined with a `MatchAny`
(default) or `MatchAll` condition, each carrying a severity and optional MITRE
ATT&CK technique IDs. The built-in ruleset covers the EICAR test file, embedded
PE/ELF executables, PHP/JSP/ASPX webshells, reverse shells, encoded PowerShell,
PDF JavaScript/auto-launch, Office auto-exec macros, and embedded HTML/script
polyglots.

Matches at or above the configured **block severity** (default `high`) reject
the upload with `403`; lower-severity matches are logged but allowed. Scanning
runs inline (in-memory, allocation-light) and the engine is compiled once.

### `file_security` middleware configuration keys

| Key | Description | Default |
|-----|-------------|---------|
| `enable_signature_scan` | Enable the YARA-lite engine. | `true` |
| `signature_rules_path` | Path to a JSON file of custom rules appended to the built-ins (invalid files fall back to built-ins). | _unset_ |
| `signature_block_severity` | Minimum match severity that blocks an upload (`low`/`medium`/`high`/`critical`). | `high` |

Custom rules file format (JSON array of rules):

```json
[
  {
    "name": "custom_marker",
    "severity": "high",
    "mitre": ["T1059"],
    "mode": "any",
    "strings": [{ "text": "DANGEROUS_TOKEN", "case_insensitive": true }]
  }
]
```

## Security posture endpoint

```
GET /v1/security/posture
```

Requires authentication with read permission on the global resource (same RBAC
gate as `/v1/diagnostics`). It returns a JSON snapshot of the gateway's
defensive subsystems:

```jsonc
{
  "version": "1.2.3",
  "generated_at": "2026-06-15T18:09:00Z",
  "waf": {
    "enabled": true,
    "auto_update": true,
    "last_updated": "2026-06-14T02:00:00Z"
  },
  "clamav": {
    "enabled": true,
    "installed": true,
    "last_scan": "2026-06-15T03:00:00Z",
    "last_result": "no threats found"
  },
  "signatures": {
    "enabled": true,
    "rule_count": 11
  },
  "fim": {
    "enabled": true,
    "watched_paths": ["/etc/gateon", "/var/www/static"],
    "baseline_files": 128,
    "last_scan": "2026-06-15T18:05:00Z",
    "total_drift": 0,
    "recent_events": []
  }
}
```

The `fim` section is omitted when FIM is disabled. The endpoint never fails on a
partially-initialized server: if posture cannot be assembled it returns a
minimal report containing the build version and timestamp.

## Measuring false positives

`make test-fp` reports two numbers, because the gateway refuses requests for two
different reasons and one number cannot cover both.

**Request content — the WAF.** 405 samples of traffic ordinary applications
serve, replayed at paranoia 1 and 2
(`internal/middleware/security/waf/testdata/benign/*.jsonl`). Refusals that exist today carry
a written reason; the build fails on any new one, and also when a recorded one
starts passing, so a fix is promoted rather than left in the file.

**Client identity and history — the always-on chain.** Replayed *sessions*
against the three middlewares every route carries — IP mitigation, user
mitigation and the reputation blocker
(`internal/middleware/chain_fp_test.go`). The question here is different: not
"is this request an attack?" but "does one client's behaviour refuse another?"

That second number needs its own harness because a stateless corpus cannot
produce the state those controls act on, and all three defects found in that
area were silent — a reputation score keyed on a browser build rather than a
client, an allowlist honoured by one code path out of five, and a 24-hour ban on
a single trap hit. Scenarios cover the shapes a real deployment produces: the
same browser on different networks, a compromised machine behind a corporate
NAT, a monitoring probe on a schedule, a crawler, a phone changing cell, and an
attacker rotating addresses.

The harness carries its own negative test. A gate that cannot observe a refusal
reports zero forever, and the zero gets quoted.

The opt-in controls — tarpit, proof-of-work, deception — are deliberately not in
either number: a scenario that enabled them would measure one deployment's
configuration rather than the shipped default.
