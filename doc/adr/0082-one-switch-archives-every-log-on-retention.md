# 82. One switch archives every log on retention

Date: 2026-11-02

## Status

Accepted.

## Context

Three records can be archived before retention removes them, each with its own
switch, all off by default:

- traces: `log.trace_archive_enabled` ([ADR 0022](0022-traces-are-archived-an-hour-at-a-time.md));
- security threats: `log.security_threat_archive_enabled` ([ADR 0066](0066-expired-security-threats-and-audit-entries-are-archived-before-they-are-deleted.md));
- audit entries: `audit.archive_on_retention` (ADR 0066).

An operator who wants nothing lost to retention has to find three switches on
three cards, and a fourth record archived later would add a fourth. Nothing
said "keep everything", so nothing could check that it held.

## Decision

**`log.archive_on_retention` archives every log retention removes.** Each
archive asks for its effective switch on every pass, as before, and now reads
it as its own switch **or** this one. A saved change applies at the next pass,
with no restart.

**It only ever adds an archive.** With it off, each per-log switch decides for
its own log exactly as before, so turning it off returns an install to where it
was. It cannot be used to switch an archive off.

**Precedence, most specific last.** The tier's default, then the stored
setting, then `GATEON_ARCHIVE_ON_RETENTION`, then each archive's own
`GATEON_TRACE_ARCHIVE_ENABLED` / `GATEON_THREAT_ARCHIVE_ENABLED`. A container
can therefore pin one archive off while the switch keeps the rest on. A value
`strconv.ParseBool` does not accept is ignored, as every archive variable is.

**Off on every tier** (`TierDefaults.ArchiveOnRetention`). Turning it on writes
three archives to a disk every existing install has budgeted for something
else; a default that changed would re-price every install without anyone
choosing it. Each archive stays bounded by its own size limit, so the switch
adds no unbounded growth.

**Administrator-only, and audited.** It archives audit entries too, so switching
it off lets retention delete an audit trail it used to keep — the reason
`log.audit_log_retention_days` is administrator-only
([ADR 0040](0040-the-security-boundary-in-global-settings-needs-an-administrator.md)). The field is `Boundary` in `globalbound` and is one
of the record fields whose change is itself audited.

## Consequences

- The dashboard has one card, *Archive everything on retention*, above the
  per-log cards. While it is on, each per-log switch reads on and is locked,
  with the reason, so the dashboard never shows an archive as off that is
  running.
- A future archive is added to the switch by reading
  `config.ArchiveOnRetentionFor` beside its own setting.
- Proven per transport in `internal/server/archive_on_retention_transport_test.go`:
  a REST save (the dashboard's JSON) and a gRPC save each turn every archive on
  and off, and an operator's save is refused on both.
