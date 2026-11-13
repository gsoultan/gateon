# 87. A root helper installs what the gateway verified, and puts the old binary back

Date: 2026-11-13

## Status

Accepted. Second of three, after ADR 0085: this record covers installing a
release and undoing a failed install. The restart it performs is a stop and a
start, which refuses connections for a few seconds; handing the listening
sockets to the new process is the third record.

Amended by ADR 0088: the stop and start described below is now one restart,
with the binary renamed into place first.

## Context

ADR 0085 lets a gateway learn, from a signed list, that a newer release
exists. Acting on that was still a person's job: download a package, install
it, watch the service come back. A gateway that tells an operator it is three
releases behind and then does nothing about it is a notice, not an upgrade.

The gateway cannot do it alone, and must not be able to. ADR 0019 runs it as
an unprivileged account under `ProtectSystem=strict`, so it cannot write
`/usr/bin/gateon`, and that is the point: the gateway is the process that
parses hostile traffic, and a gateway that can replace its own binary turns
any code-execution bug in a parser into persistence as whatever that binary
runs as next. Loosening the unit so the feature can work would trade a
hardening that protects every install for a convenience.

So something privileged has to do the replacing, and the question is what it
may believe. Its caller is the gateway. If it believes the gateway's word
about what to install, the privileged step adds nothing.

A second problem is what happens after a bad release. Putting the old binary
back is easy; putting it back onto a database the new binary has already
migrated is not, because migrations are forward-only and the old binary does
not know the new schema.

## Decision

An install is two programs with a signature between them.

**The gateway's half** (`internal/selfupdate/upgrade`) downloads the release
into `upgrade/` under its own data directory, verifies the list's Ed25519
signature and the archive's SHA-256, and then writes `request.json`, last and
atomically. It can start this only for the newest release the last check
verified, named exactly by the caller, on a systemd install whose helper is
enabled, from a release build that carries a release key.

**The helper** (`internal/selfupdate/helper`, run by `gateon-upgrade.service`
as root, started by `gateon-upgrade.path` when the request appears) is written
as if the gateway were compromised:

- It believes one thing from the gateway: bytes signed by a release key
  compiled into the binary root already has installed. It verifies the same
  list and the same archive again and takes nothing from the gateway's own
  conclusion.
- The request names a version and nothing else. Which file, which hash and
  whether it may be installed come from the signed list and from the installed
  version. A request cannot ask for a release that is not newer; only
  `gateon upgrade --allow-downgrade` at a root shell can, so replaying an old,
  validly signed release with a known hole is not something a compromised
  gateway can ask root to do.
- Every file is opened beneath the gateway's data directory through `os.Root`,
  as a regular file within a size bound, so a symlink cannot make root read or
  delete something else and a FIFO cannot hang it.
- The archive is copied into the helper's own directory before it is hashed,
  so what is unpacked is what was verified. Nothing is parsed as an archive
  until its hash has matched, and nothing the gateway wrote is executed.
- The unit is confined although it is root: `ProtectSystem=strict` with only
  the binary's directory and the two state directories writable, and
  `PrivateNetwork=true`. The helper never touches the network; downloading is
  the unprivileged half's job.

**The swap** keeps the replaced binary in `/var/lib/gateon-upgrade`, stops the
service, renames the new binary into place and starts the service. The helper
then waits for the new gateway to say it is ready. It does not probe a port:
which port, and whether it speaks TLS, is configuration the helper would have
to read from files the gateway owns. Instead the helper leaves a fresh nonce
in its root-owned status while the service is stopped, and the gateway of the
expected version writes the nonce back once every listener has bound and
`/readyz` would answer 200. Only the binary just started can read that nonce
in time.

**Rollback.** No answer within `GATEON_UPGRADE_READY_TIMEOUT` (90 s), or three
restarts by systemd, and the helper puts the old binary back and starts it.
What it may do about the database decides the rest:

- Every gateway records, before it migrates a database an earlier version
  used, that it is about to, and copies a SQLite database aside first
  (`VACUUM INTO`, one slot, `<db>.pre-upgrade.bak`). A migration does not run
  if its copy cannot be made.
- If the failed release migrated only SQLite databases that have a copy, the
  helper rolls back and orders the copy restored. The old gateway does the
  restoring, as its own account on its own files, before it opens any store,
  and only while the helper is waiting for it: a status left over from a
  finished rollback orders nothing, so a later downgrade by hand never loses
  data to it. What the failed release wrote is kept beside the database.
- If it migrated PostgreSQL, or SQLite with the copy switched off, the helper
  does not put the old binary back. It would start on a schema it does not
  know. The install is reported as failed and not rolled back, and
  `doc/self-upgrade.md` says what to do.

**Who may start one.** The dashboard's Upgrade button, `POST
/v1/update/install` and the `InstallUpdate` RPC are one code path, and it
requires the admin role in the service, not in the UI. `gateon upgrade` is
the same install for an operator who is already root; it downloads into a
directory of root's own and needs no running gateway.

**Automatic install** is off on every tier. Switched on, it installs the
newest verified release inside a daily window (02:00 to 04:00 local unless
set), and by default only a patch release. A release the helper already tried
and did not keep is never installed automatically again.

Containers, pods, hand-started binaries and Windows are not upgraded this
way. Their version belongs to whatever started them, and the dashboard says
so.

## Consequences

- A new root-owned unit ships in the package. On a first install the watcher
  is enabled; a package upgrade leaves it as the operator had it, so no
  existing host gains a root-triggered path it did not ask for. Until it is
  enabled the dashboard shows the command instead of a button.
- An upgrade is a restart: a few seconds of refused connections, longer when a
  large SQLite database is copied first. The third record in this series is to remove the gap.
- A SQLite install needs free disk equal to its database at each release that
  migrates, and its start takes as long as the copy. `GATEON_MIGRATION_BACKUP=0`
  turns the copy off, at the price that a failed upgrade which migrated is no
  longer rolled back. This applies to upgrades by package manager too.
- A helper-installed binary is newer than the package manager's record of it.
  A later package upgrade overwrites it as usual.
- The helper replaces the binary and nothing else. A release that changes the
  unit file still needs the package.
- The gateway's statements about itself (ready, migrated) are believed. A
  compromised gateway can use them to choose between two binaries that were
  each verified, and to nothing else.

## Alternatives considered

- **The gateway replaces its own binary.** Simplest, and it means making the
  binary writable by the account that parses hostile traffic. Rejected for
  the reason ADR 0019 exists.
- **The helper downloads the release itself.** Then nothing the gateway
  writes would matter at all, but the root process would speak TLS to the
  internet and parse what comes back. Keeping the network on the unprivileged
  side and giving root a signature to check is the smaller attack surface.
- **A setuid helper, or a sudoers rule.** Both make the privileged step
  callable by anything running as the gateway's account at any time, with
  arguments. A path unit that takes no arguments and reads one fixed file is
  narrower, and systemd already ships it.
- **Probing `/readyz` from the helper.** Needs the management listener's
  address and TLS settings, which live in files the gateway can rewrite, and
  fails on a host where the management port is bound to another interface.
- **Always rolling the binary back.** Starts the old version on a schema it
  has not seen. It may work, and when it does not the failure is corrupt
  rows rather than a clear refusal.
- **Reversible migrations.** The right answer in the long run and a change to
  every migration ever written. A copy taken beforehand gives the same result
  for SQLite today.
