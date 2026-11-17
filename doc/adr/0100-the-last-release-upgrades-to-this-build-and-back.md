# 100. The last release upgrades to this build and back

Date: 2026-11-17

## Status

Accepted. Builds on ADR 0087 (install and roll back) and ADR 0092 (sockets
kept open across the restart).

## Context

A gateway that upgrades itself rolls back by putting the previous binary back
(ADR 0087). That only works if the previous binary can start on what the new
one left behind: the configuration files it rewrote and the database it
migrated. Nothing checked that. The migration runner applies whatever is
pending and an older binary ignores rows in `migrations` it does not know, so
an additive migration is harmless to it and a column dropped or renamed is
not. Which of the two a change was depended on whoever wrote it remembering.

The cost of forgetting is specific. On SQLite the helper restores the copy
taken before the migration, so the rollback works and loses what the new
version wrote. On PostgreSQL there is no copy; the helper refuses to roll
back at all, and the gateway is left on a version that does not start. And an
upgrade by package manager has no helper: `apt install gateon=<previous>`
simply starts the old binary on the new schema.

Every test in the tree ran this build against itself.

## Decision

**From v1.3.8 on, every change is backward compatible with the latest
release.** Stated as what must work:

1. This build starts, becomes ready and proxies on the configuration and the
   database the latest release wrote.
2. The latest release starts, becomes ready and proxies on what this build
   left behind, with nothing restored.
3. A restart from the latest release into this build refuses no connection
   made after the old process has gone.

The second is the one that constrains a change. A migration may add a table,
a column with a default, or an index. It may not drop, rename or narrow
something the latest release reads, and it may not write a value the latest
release cannot parse into a column it does read. Removing something takes two
releases: stop reading it in one, drop it in the next. The same holds for a
field in a configuration file.

**The rule is a test, and the test runs the release's own binary.**
`tests/e2e/compat_test.go` starts the two binaries as real processes on one
state: the release creates it, this build runs on it, the release runs on it
again. On SQLite and on a new PostgreSQL database. `make check-compat`
downloads the latest release's tarball, checks it against that release's
`checksums.txt`, and runs those specs. CI runs it in `build`, which is a
required check.

**Nothing in it may skip.** Without the release binary or without PostgreSQL
the specs fail rather than skip when `GATEON_COMPAT_REQUIRED=1`, which the
script sets. In the ordinary test run they skip, because that run has no
release to compare against.

**"The latest release" is whatever GitHub says it is on the day.** On `main`
after v1.3.9 is published the comparison is against v1.3.9. That is the rule
as asked for: compatible with the latest previous version, not with every
version ever shipped.

## Consequences

- A change that breaks a rollback fails CI on the pull request that makes it,
  with the previous release's own log in the test output.
- An upgrade that skips releases is covered only transitively. Each adjacent
  pair was held to the rule, and additive changes compose, but v1.3.8 to
  v1.4.2 directly was never run. The helper still restores the SQLite copy on
  a rollback, which does not depend on the rule.
- The helper still refuses to roll back after a PostgreSQL migration. With
  this rule a rollback there would be sound between adjacent releases;
  allowing it is a separate decision, because the helper would have to know
  the upgrade was from the adjacent release.
- A restart out of the latest release is the latest release's own shutdown.
  A request it drops on its way out (ADR 0101, fixed in the build after
  v1.3.8) is reported by the spec and not held against this build. Everything
  after the old process exits is.
- CI needs the network to reach the release. A release that was deleted, or a
  tarball that does not match its checksums, fails the build, which is the
  right answer to both.
- The first release with a real breaking need has to do it in two steps, or
  change this ADR in the open.

## Alternatives

- **A linter over migration SQL** (no `DROP`, no `RENAME`). Catches the
  obvious half. Misses a value written in a new format, a configuration field
  whose meaning changed, and anything outside SQL. Running the old binary
  catches what it actually cannot do.
- **Down migrations.** A second thing to write and to get wrong for every
  migration, exercised only when an upgrade has already failed. The additive
  rule needs none.
- **Compare against a pinned version.** Stable, and wrong the day after a
  release: the rule is about the latest one.
