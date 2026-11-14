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

`GATEON_MIGRATION_BACKUP=false` turns the copy off. A failed upgrade that
migrated is then not rolled back (see below).

PostgreSQL is migrated in place. Take a backup of your own before a release
whose notes mention a migration: see [backup-restore.md](backup-restore.md).

## When an upgrade fails

Settings, Updates shows how the last install ended, and
`journalctl -u gateon-upgrade` has the helper's own account of it.

| Outcome | What it means | What to do |
| :--- | :--- | :--- |
| **Not installed** | The release was refused before anything changed: signature, checksum, download, or not newer. | Read the reason shown. For a mirror, check it copies `checksums.txt` and `checksums.txt.sig` unmodified. |
| **Rolled back** | The new version did not become ready and the previous one is running again. If the new version had migrated a SQLite database, the copy taken beforehand was put back and what the new version wrote is kept as `<database>.failed-upgrade`. | `journalctl -u gateon` from the time of the upgrade says why the new version was not ready. Report it before trying again. |
| **Failed, not rolled back** | The new version is installed and not ready, and it had already migrated PostgreSQL (or SQLite with the copy switched off). The previous binary was not put back, because it would start on a schema it does not know. | Fix what stops the new version starting (`journalctl -u gateon`), or restore the database from your backup and run `sudo gateon upgrade --version <previous> --allow-downgrade`. |

The previous binary stays at `/var/lib/gateon-upgrade/previous-gateon` until
the next upgrade replaces it.

## Downgrading

A request from the gateway can never install an older release. An operator
can:

```bash
sudo gateon upgrade --version 1.8.2 --allow-downgrade
```

Migrations are forward-only. Downgrading across a release that migrated needs
the database from before that release.

## Tunables

| Variable | Default | Effect |
| :--- | :--- | :--- |
| `GATEON_UPGRADE_READY_TIMEOUT` | `90s` on every profile | How long a new binary has to report ready before the previous one is put back. A Go duration, held between `15s` and `15m`. Read by the helper from `/etc/default/gateon`. |
| `GATEON_MIGRATION_BACKUP` | on, on every profile | `false` skips the SQLite copy before a migration. |
| `GATEON_SOCKET_HANDOFF` | on, on every profile | `false` binds every listener afresh at each start, so a restart refuses connections for a few seconds as it did before. |
| `GATEON_UPDATE_AUTO_INSTALL`, `GATEON_UPDATE_AUTO_SCOPE`, `GATEON_UPDATE_WINDOW` | off, `patch`, `02:00-04:00` | See *Upgrading automatically*. |

## What it does not do

- It replaces the binary only. A release that changes `gateon.service` still
  needs the package.
- The package manager's record of the installed version is not updated. A
  later `apt upgrade` or `dnf upgrade` installs over it as usual.
- It does not carry a live connection from the old gateway to the new one.
  Long-lived connections are closed at the restart and reconnect.
