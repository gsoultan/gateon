# 104. An operator rolls an upgrade back, and PostgreSQL is dumped first

Date: 2026-11-22

## Status

Accepted. Builds on ADR 0087 (a root helper installs what the gateway
verified) and ADR 0102 (the last release upgrades to this build and back).

## Context

ADR 0087 rolls an upgrade back in one case: the new binary does not report
ready. The helper is holding the previous binary and puts it back.

An upgrade that fails differently had no way back. A release that starts,
reports ready and then misbehaves, with a route that no longer matches or
memory that grows, left the operator with `gateon upgrade --version <old>
--allow-downgrade`: a download and a signature check, at the moment the
release source may be the thing that is unreachable, for a binary that was
already on the host at `/var/lib/gateon-upgrade/previous-gateon`.

And the database had one unprotected half. A SQLite file is copied before a
newer gateway migrates it. A PostgreSQL database was migrated in place with
nothing taken first, so an upgrade across more than one release that went
wrong had no way back except backups the operator may not have had.

## Decision

### A rollback on request

The helper puts back the release the last upgrade replaced when an operator
asks: `sudo gateon upgrade --rollback`, **Settings, Updates, Roll back**, or
`POST /v1/update/rollback` (the `RollbackUpdate` RPC). Nothing is downloaded.
It is the same swap, single restart and wait for a nonce as an install.

**Which release goes back is the helper's record, never the request.** The
helper keeps one binary. `upgrade.PreviousOf` reads the newest entry of its
history that changed the installed binary, and that entry must be an install
of exactly the installed release. So there is a rollback to offer after an
upgrade, and none after a rollback, after an upgrade that rolled itself back,
or after a package installed something else. A request names the release its
asker was shown; the helper refuses when that is not the one it kept.

**A rollback that does not come up goes forward again.** The helper keeps the
binary it is replacing while it waits. If the previous release does not
report ready, that binary is put back and restarted, and the outcome says so.
Asking for a rollback never leaves a host worse off than not asking.

**The database stays as it is.** A release is built compatible with the one
before it (ADR 0102): its migrations only add, and that release is tested by
starting it on a database this one migrated. So after an upgrade one release
forward the previous release runs on the database as it stands, and a
rollback loses nothing written since the upgrade. Restoring the copy taken
before the migration would discard every route, login and setting made since,
to undo a schema change that does not need undoing.

When the installed release migrated and was *not* built compatible with the
previous one, an upgrade across releases or a build that was not a release,
the only way back is that copy. The helper refuses with `needs_restore`
unless `--restore-database` was given at a root shell, and then only when
every migrated database is SQLite with a copy. What was written since is kept
as `<database>.failed-upgrade`.

### The trust boundary this moves

ADR 0087 says a request from the gateway can never install an older release.
This narrows that: the gateway's account can now have root install one older
binary. `sec` co-signs on these grounds, each of which is a test:

- It is one binary, the one root itself copied from the installed path
  before the last upgrade and kept in a directory only root writes. The
  request cannot name a file, a version other than that one, or a source.
- It is one step. After a rollback there is nothing to roll back to.
- A request file cannot order a database restored. `restore_database` is not
  a field of a request, and a request carrying it is refused unread.
- The RPC requires the administrator role on every transport, like
  `InstallUpdate`, and is in the RBAC table under the same permission.
- Disabling `gateon-upgrade.path` turns it off with everything else.

What it does allow: an administrator, or whoever holds an administrator's
session, can return the gateway to the release it ran before its last
upgrade, including when that upgrade fixed a vulnerability. An administrator
can already switch the WAF off; this is not a larger power than that one.
The rollback is written to the audit log.

### The status a rollback writes

In an upgrade the helper is the old release and the gateway that answers it
is the new one. In a rollback it is the other way round: the helper is the
newer release, and the gateway reading its status is the older one, which
decodes that file refusing unknown fields. A status holding a field added
since would never be answered.

So a rollback's status carries only what the first release with a helper
(1.3.8) declared, and tells itself apart by `reason` alone, which is a
string to every release: `requested`, `no_previous`, `needs_restore`,
`previous_not_ready`. No phase was added and no field is set that 1.3.8 does
not know. `TestTheRollbackStatusIsReadableByTheFirstHelperRelease` holds the
shape, and `make check-compat` holds the behaviour: this tree's helper puts
the last release's own binary back and waits for it to answer.

### PostgreSQL is dumped before it is migrated

Before the first pending migration of a PostgreSQL database an earlier
gateway used, the gateway runs `pg_dump --format=custom` on the schema it
uses and writes `<data dir>/postgres-<database>.pre-upgrade.dump`, mode
0600, one slot, replaced only by a complete new dump. The connection is
passed in `pg_dump`'s environment, never on its command line.

What a dump that cannot be taken costs depends on whether anything can undo
the refusal:

- **The helper is waiting for this gateway** (`upgrade.Awaited`): the
  migration does not run and the gateway does not start. The helper puts the
  previous release back on a database nothing touched.
- **Any other start**, a package upgrade or a new container image: the
  gateway logs that it is migrating without a dump, and migrates. Nobody is
  there to put anything back, the release image has no `pg_dump`, and
  refusing to start would turn a missing client program into an outage.

A migration whose backup could not be taken is taken out of the record the
helper reads (`MigrationObserver.Abandon`). Left there it said a database had
been migrated, and across releases the helper would have left a gateway that
cannot start installed over a database that was never changed.

**Nothing restores the dump by itself.** A PostgreSQL database may be shared
by several gateways, and replacing it beneath the others is not something one
of them decides at start-up. The dump is for an operator with `pg_restore`.
The rules for PostgreSQL are otherwise unchanged: one release forward the
previous release runs on the migrated database, and across releases a
rollback is refused, now with a dump to restore from.

## Consequences

- Every upgrade the helper performs can be undone, on request, by something
  already on the host.
- A host on PostgreSQL needs the PostgreSQL client tools, of the server's
  version or newer, for a self-upgrade that migrates. Without them the
  upgrade is rolled back and the journal says why.
  `GATEON_MIGRATION_BACKUP=false` turns the dump off along with the SQLite
  copy; no new tunable was added.
- The dump needs free disk about equal to the database and is bounded at
  twelve minutes, inside the fifteen the helper waits for a gateway that is
  backing up.
- A release that the operator rolled back from is not installed
  automatically again, by the rule that already covers a failed one.
- `make check-compat` now needs `/var/lib/gateon-upgrade`, which every
  release reads at that fixed path. The script creates and removes it and the
  spec refuses a directory holding a real helper's record.

## Alternatives considered

- **Restore the database on every rollback.** Symmetrical with the failed
  upgrade, and wrong for this case: the gateway has been serving, so the copy
  is stale by everything done since.
- **Copy PostgreSQL inside PostgreSQL** (a spare schema). No client tools
  needed, but it doubles the database on the server, where disk is someone
  else's budget, and leaves a copy that only this code knows how to read.
- **Refuse to migrate PostgreSQL without a dump on every start.** One rule
  instead of two, and an outage on every container and package upgrade that
  lacks `pg_dump`, with nothing to roll back to.
- **A new status field or phase for rollbacks.** Clearer in this release's
  code and unreadable by the release being rolled back to.
