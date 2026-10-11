# 66. Expired security threats and audit entries are archived before they are deleted

Date: 2026-10-11

## Status

Accepted.

## Context

An operator asked for the logs that pass their retention period to be archived
rather than lost, and for the archive to be readable in the dashboard, without
adding load to the database.

Access logs already worked this way ([ADR 0022](0022-traces-are-archived-an-hour-at-a-time.md)).
The other two records did not:

- **Security threats** were deleted outright, by one `DELETE ... WHERE
  timestamp < ?` per hour. A threat row carries request and response bodies, so
  that statement could hold SQLite's write lock for as long as it took to remove
  a whole day's attack traffic.
- **Audit entries** had two owners. The audit manager archived them once a day,
  on `audit.retention_days`. The telemetry prune also deleted them every hour,
  on `log.audit_log_retention_days`, and never archived. The dashboard saves the
  second setting as 90 by default. With audit retention at 365 and archiving
  on, entries between 90 and 365 days old were therefore deleted without ever
  reaching an archive. The archive step also read every expired row into memory
  at once.

## Decision

**One owner per table, and the archive comes first.** The audit manager is the
only thing that deletes audit entries. It applies the shorter of the two
settings, so nothing is kept longer than before the change. The telemetry prune
still deletes security threats, but hands them to a `telemetry.ThreatArchiver`
first when one is installed and enabled.

**Retention works a chunk at a time and deletes by id.** Each step reads the
oldest expired rows, at most 5,000 audit entries or 1,000 threats. It writes
them to one archive file, then deletes exactly those ids. A step whose archive
fails deletes nothing, and the next run retries it. One run is capped at 200
audit chunks or 500 threat chunks, so a large backlog drains over several runs
instead of in one long pass. This bounds three things:

- the memory a step holds;
- the size of each archive file;
- how long any single DELETE holds the write lock.

**Security threats go to files, not to another table.** The new package
`internal/telemetry/threatarchive` writes one gzip-compressed NDJSON file per
chunk under `<data dir>/security/archives`. Each file is named for its oldest
and newest threat. It is written to a temporary name, synced, and renamed into
place, so a reader never sees a partial file under a real name.

**Archived threats are read from the files.** Listing and searching them is
paged and never queries the database. That is the point of archiving: the
database stops paying for history nobody is looking at. The search is a
substring scan of one bounded file, and decompression is capped at 1 GiB.

Defaults and overrides:

- The archive is **off on every tier**. Turning it on writes to disk that every
  existing install has budgeted for something else, so a default of "on"
  would re-price every install.
- `log.security_threat_archive_enabled` or `GATEON_THREAT_ARCHIVE_ENABLED`
  turns it on.
- The size budget comes from `TierDefaults.ThreatArchiveMaxBytes`: 256 MiB,
  1 GiB or 10 GiB. `GATEON_THREAT_ARCHIVE_MAX_MB` overrides it.
- When the budget is reached, the oldest files are removed first. The file just
  written is never removed, because its rows are deleted as soon as the archive
  reports success.

## Consequences

- **Audit timing.** Audit entries that used to be pruned hourly by
  `log.audit_log_retention_days` are now pruned by the audit manager's daily
  run, so an entry can outlive the setting by up to a day.
- **Dashboard.** The Security Hub has an Archive tab that lists the files and
  opens one with search and paging. Every value in it is attacker-written, so
  it is rendered only as React text. The tab offers no mitigation, because the
  row behind an archived threat no longer exists.
- **Several gateways on one database.** Each gateway runs its own prune. Two
  gateways that read the same chunk at the same moment can both archive it, so
  a threat may appear in two files. The delete is by id, so nothing is lost;
  the duplicate is the price of not coordinating the prune.
- **Package size.** `internal/telemetry` is at its pinned file count, so the
  archive is a package of its own, and the prune reaches it only through the
  `ThreatArchiver` interface.
