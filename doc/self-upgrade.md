# Upgrading a gateway from the gateway

A gateon installed as a systemd service can install a newer release itself:
from **Settings, Updates** in the dashboard, with `sudo gateon upgrade` on the
host, or on its own inside a maintenance window. The design and its reasons
are in [ADR 0087](adr/0087-a-root-helper-installs-what-the-gateway-verified.md);
this page is how to use it and what to do when it goes wrong.

A container, a Kubernetes pod and a binary started by hand are not upgraded
this way. Their version belongs to whatever started them, and Settings shows
the command for that instead.

## What happens during an upgrade

1. The gateway downloads the release into `/var/lib/gateon/upgrade/` and
   checks the release list's signature and the archive's SHA-256.
2. It leaves a request there. `gateon-upgrade.path` notices and starts
   `gateon-upgrade.service`, which runs as root.
3. The helper checks the signature and the SHA-256 again, with the release
   key compiled into the binary already installed. It installs only a release
   newer than the installed one.
4. It copies the installed binary to `/var/lib/gateon-upgrade/previous-gateon`,
   puts the new binary in place and restarts the service once. systemd keeps
   the listening sockets open across that restart, so **a connection made
   while the gateway restarts waits and is served**. See *Connections during
   the restart*.
5. The new gateway reports ready once every listener has bound. If it does not
   within 90 seconds, or systemd restarts it three times, the helper puts the
   previous binary back and restarts the service.

## Connections during the restart

The gateway hands each listening socket to systemd when it binds it. systemd
holds the socket while the gateway is replaced and gives it to the new
process (ADR 0092).

| Connection | What happens |
| :--- | :--- |
| Made while the gateway restarts | Waits, then is served by the new gateway. |
| Accepted by the old gateway, request not sent yet | Answered by the old gateway before it exits (ADR 0101). It waits up to one second for the request. |
| A request in flight | Finished by the old gateway before it exits. |
| Long-lived: WebSocket, SSE, a TCP session, HTTP/3 | Closed when the old gateway's drain ends. The client reconnects. |

This needs `NotifyAccess=main` and `FileDescriptorStoreMax=64` in
`gateon.service`. The packages and `gateon install` write them from this
release on. A host upgraded by the helper keeps its old unit; see
`upgrading.md`. Check with:

```sh
systemctl show gateon -p NFileDescriptorStore
```

It prints the number of sockets systemd is holding, one per listener.
`systemctl stop gateon` closes them.

## Compatibility with the previous release

Every release is held to one rule: the release before it can be upgraded to
it and rolled back again. The new version starts on the configuration and the
database the previous one wrote, and the previous one starts again on what
the new one left, with nothing restored (ADR 0102). A rollback, by the helper,
on request (see *Rolling back*) or by installing the older package, depends
on the second half.

The rule is checked on every pull request by running the previous release's
own binary against the build, on SQLite and on PostgreSQL
(`make check-compat`). It covers one release back. Upgrading across several
releases at once is covered only because each step was.

## Before the first upgrade

The package enables the helper's watcher on a first install. On a host that
was upgraded to this release with a package manager it is installed but left
off, and Settings shows this command instead of an Upgrade button:

```bash
sudo systemctl enable --now gateon-upgrade.path
```

To switch self-upgrade off for a host, disable the same unit. The gateway
then has no way to ask root for anything.

A release is installed only if it is signed by a key compiled into the
installed binary. A build with no release key (a development build, or a
release made before the project's key was added) verifies nothing and
installs nothing.

## Upgrading by hand

In the dashboard: **Settings, Updates, Install, Upgrade to vX.Y.Z**. Only an
administrator sees the button enabled. The confirmation names the version and
what the restart costs. The page follows the install through the restart and
shows how it ended.

On the host:

```bash
sudo gateon upgrade                  # the newest release
sudo gateon upgrade --version 1.8.3  # a named one
sudo gateon upgrade --yes            # no confirmation, for a script
```

`gateon upgrade` is the same install without the gateway's half: root
downloads and verifies, then installs. It works when the gateway is stopped
or will not start, which is when it is needed most.

Over the API, for automation: `POST /v1/update/install` with
`{"version": "1.8.3"}`, or the `InstallUpdate` RPC over Connect or gRPC. Both
require the admin role, and the version must be the newest one the last check
verified. `GET /v1/update/status` reports progress and history.

## Rolling back

An upgrade that started and then misbehaves can be undone without
downloading anything. The helper keeps the binary the last upgrade replaced,
and puts it back when asked (ADR 0104).

In the dashboard: **Settings, Updates, Install, Roll back to vX.Y.Z**. Only
an administrator sees the button enabled. The confirmation names both
versions. The button is there only while the host holds a version to go back
to.

On the host:

```bash
sudo gateon upgrade --rollback          # the release the last upgrade replaced
sudo gateon upgrade --rollback --yes    # no confirmation, for a script
```

Over the API: `POST /v1/update/rollback` with `{"version": "1.8.2"}`, or the
`RollbackUpdate` RPC. Both require the admin role, and the version must be
the one `GET /v1/update/status` reports as `rollbackVersion`.

What it does:

- **One step back, once.** It goes to the release installed immediately
  before the last upgrade. After a rollback there is nothing further to roll
  back to; for any other release see *Downgrading*.
- **The database is left as it is.** After an upgrade one release forward the
  previous release runs on the migrated database (see *Compatibility with the
  previous release*), so nothing written since the upgrade is lost.
- **If the previous release does not come up, the newer one is put back.**
  The helper waits for the previous release to report ready as it does for
  an upgrade, and restores what was running when it does not.
- **The release rolled back from is not installed automatically again.** An
  administrator can still install it by hand.

After an upgrade across several releases at once, or from a build that was
not a release, the previous release was never tested on the migrated
database. A rollback is then refused from the dashboard and by the plain
command. On SQLite the copy taken before the upgrade can be put back with it:

```bash
sudo gateon upgrade --rollback --restore-database
```

That sets aside everything written since the upgrade, as
`<database>.failed-upgrade`, and is only ever done from a root shell. On
PostgreSQL restore the dump yourself first (see *The database*), then
downgrade.

## Upgrading automatically

Off by default. Under **Settings, Updates, Automatic install**:

| Setting | Default | Environment |
| :--- | :--- | :--- |
| Install new versions automatically | off | `GATEON_UPDATE_AUTO_INSTALL` (`true`/`false`, wins over the setting) |
| Which releases | patch releases only | `GATEON_UPDATE_AUTO_SCOPE` (`patch`, `minor`, `major`) when the setting is unset |
| Window | 02:00 to 04:00, the host's local time | `GATEON_UPDATE_WINDOW` (`HH:MM-HH:MM`) when the setting is empty |

The gateway installs the newest verified release when the daily check has
found one, the scope allows it and the clock is inside the window. A release
that was rolled back, refused or left failed is not tried automatically
again; an administrator can still install it by hand.

## The database

Before a gateway migrates a database that an earlier version used, it copies
a SQLite database to `<database>.pre-upgrade.bak`. One copy is kept; the next
migrating upgrade replaces it. The copy needs free disk equal to the
database, and a migration does not run if the copy cannot be made. This
applies to every upgrade, including one by package manager.

PostgreSQL is dumped first, with `pg_dump`, to
`<data dir>/postgres-<database>.pre-upgrade.dump` (ADR 0104). The dump holds
the schema the gateway uses, in the custom format `pg_restore` reads. One
dump is kept per database and the next migrating upgrade replaces it. It
needs the PostgreSQL client tools on the gateway's host, of the server's
version or newer:

```bash
sudo apt install postgresql-client    # Debian, Ubuntu
sudo dnf install postgresql           # Fedora, RHEL
```

| How the new version was started | No dump could be taken |
| :--- | :--- |
| By the upgrade helper (dashboard, `gateon upgrade`, automatic) | The database is not migrated, the new version does not start, and the helper puts the previous one back. `journalctl -u gateon` names the reason. |
| By a package manager, or as a new container image | The gateway logs `MIGRATING A POSTGRESQL DATABASE WITHOUT A DUMP` and migrates. Nothing is there to put the previous version back, so it does not refuse to start. The release image has no `pg_dump`; take your own backup before changing its tag. |

Nothing restores a dump by itself, because a PostgreSQL database may be
shared by several gateways. To put one back, stop every gateway using the
database and run:

```bash
pg_restore --clean --if-exists --no-owner --dbname "$DATABASE_URL" \
  /var/lib/gateon/postgres-<database>.pre-upgrade.dump
```

`GATEON_MIGRATION_BACKUP=false` turns the copy and the dump off. A failed
upgrade that migrated is then not rolled back (see below).

PostgreSQL is migrated in place. A failed upgrade is still
rolled back when it was one release forward: each release is built knowing
the release before it and is tested by starting that release on a database
it has migrated, so the previous version runs on the newer schema and
nothing needs restoring. What the new version added stays in the database
and the previous version ignores it. An upgrade across several releases at
once is not covered by that test and is not rolled back; the dump taken
before it is what you restore from. See also
[backup-restore.md](backup-restore.md).

## When an upgrade fails

Settings, Updates shows how the last install ended, and
`journalctl -u gateon-upgrade` has the helper's own account of it.

| Outcome | What it means | What to do |
| :--- | :--- | :--- |
| **Not installed** | The release was refused before anything changed: signature, checksum, download, or not newer. | Read the reason shown. For a mirror, check it copies `checksums.txt` and `checksums.txt.sig` unmodified. |
| **Rolled back** | The new version did not become ready and the previous one is running again. If the new version had migrated a SQLite database, the copy taken beforehand was put back and what the new version wrote is kept as `<database>.failed-upgrade`. If it had migrated PostgreSQL, or SQLite with the copy switched off, and the upgrade was one release forward, the database was left as migrated and the previous version runs on it; the card says so. | `journalctl -u gateon` from the time of the upgrade says why the new version was not ready. Report it before trying again. |
| **Failed, not rolled back** | The new version is installed and not ready, it had already migrated PostgreSQL (or SQLite with the copy switched off), and the upgrade skipped a release or came from a build that was not a release. The previous binary was not put back, because it was never tested on that schema. | Fix what stops the new version starting (`journalctl -u gateon`), or restore the database from the dump taken before the upgrade (see *The database*) and run `sudo gateon upgrade --version <previous> --allow-downgrade`. |
| **Rolled back on request** | Someone asked for the previous version and it is running. The database was left as it is, unless `--restore-database` was given. | Nothing. The version rolled back from is not installed automatically again. |
| **Rollback refused** | Nothing was changed. Either there is no previous version on the host, or going back needs the database copy put back as well. | For the second, see *Rolling back*. |
| **Rollback failed** | The previous version was put back and did not become ready, so the version that was running is installed again and running. | `journalctl -u gateon` from that time says why the previous version did not start. |

The previous binary stays at `/var/lib/gateon-upgrade/previous-gateon` until
the next upgrade replaces it.

## Downgrading

To go back to the release the last upgrade replaced, use *Rolling back*: it
downloads nothing. A request from the gateway can install no other older
release. An operator can install any:

```bash
sudo gateon upgrade --version 1.8.2 --allow-downgrade
```

Migrations are forward-only. Downgrading across a release that migrated needs
the database from before that release.

## Tunables

| Variable | Default | Effect |
| :--- | :--- | :--- |
| `GATEON_UPGRADE_READY_TIMEOUT` | `90s` on every profile | How long a new binary has to report ready before the previous one is put back. A Go duration, held between `15s` and `15m`. Read by the helper from `/etc/default/gateon`. |
| `GATEON_MIGRATION_BACKUP` | on, on every profile | `false` skips the SQLite copy and the PostgreSQL dump before a migration. |
| `GATEON_SOCKET_HANDOFF` | on, on every profile | `false` binds every listener afresh at each start, so a restart refuses connections for a few seconds as it did before. |
| `GATEON_UPDATE_AUTO_INSTALL`, `GATEON_UPDATE_AUTO_SCOPE`, `GATEON_UPDATE_WINDOW` | off, `patch`, `02:00-04:00` | See *Upgrading automatically*. |

## What it does not do

- It replaces the binary only. A release that changes `gateon.service` still
  needs the package.
- The package manager's record of the installed version is not updated. A
  later `apt upgrade` or `dnf upgrade` installs over it as usual.
- It does not carry a live connection from the old gateway to the new one.
  Long-lived connections are closed at the restart and reconnect.
