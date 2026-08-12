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

**Where the token lives.** In the browser it exists only in the HttpOnly,
`SameSite=Lax` `gateon_session` cookie (`Secure` when served over TLS). It is
never written to `localStorage` or `sessionStorage`, and no script on the page
can read it. API and CLI clients send `Authorization: Bearer <token>`; query
parameters are accepted only for WebSocket and SSE, which cannot set headers.

**Known limitation — multi-instance deployments.** Binding state is cached per
process. Instances sharing one database do not currently see each other's
revocations, so a disable is immediate on the instance that performed it and
takes effect elsewhere only after that instance's cache entry is evicted or it
restarts. Single-instance and active-passive HA deployments are unaffected in
practice; see `doc/adr/0005-session-lifecycle-and-first-run-trust.md`.

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
