# 19. The packaged service runs as its own account, not root

Date: 2026-09-26

## Status

Accepted. `ops` and `sec`, with `arch`: it changes what every .deb and .rpm
install runs as, and what the process terminating hostile traffic could do if it
were taken over.

## Context

The systemd unit the packages ship, and the one `gateon install` writes, ran
`User=root`. Its only reason was privilege that capabilities now express:
ports below 1024, and eBPF, which ADR 0018 made a matter of CAP_BPF and
CAP_NET_ADMIN rather than uid 0. Everything else gateon does at runtime needs
nothing: it writes only to `/etc/gateon` and `/var/lib/gateon` —
`ProtectSystem=strict` already made the rest of the filesystem read-only, root
or not — HA moves the virtual IP with `ip addr`, which needs CAP_NET_ADMIN, and
there are no raw sockets.

So a takeover of the gateway got root on the host for no benefit to anyone.

## Decision

- **A system account, `gateon`**, created by the package's postinstall and by
  `gateon install` with the same `useradd` flags: its own group, no login
  shell, `/var/lib/gateon` as its home.
- **Three capabilities, ambient and bounding:** CAP_NET_BIND_SERVICE,
  CAP_BPF, CAP_NET_ADMIN. Ambient so the process holds them without being root
  and `ip` inherits them; the bounding set is the most it, or anything it runs,
  can ever hold. CAP_PERFMON and CAP_SYS_RESOURCE, which the unit carried for
  eBPF, are gone — the programs load without either.
- **Both directories belong to the account.** systemd hands `/var/lib/gateon`
  over by itself (`StateDirectory=` re-owns an existing tree), but leaves an
  existing `/etc/gateon` alone, so the postinstall and the installer chown both.
  Measured on systemd 259.

## Consequences

- **Behaviour change on upgrade.** A file outside the two directories that
  gateon reads must be readable by the account. The usual one is a certificate
  from certbot: `/etc/letsencrypt/archive/*/privkey*.pem` is 0600 root. Grant
  the `gateon` group read access, or deploy the certificates into
  `/etc/gateon`. To keep running as root, add a drop-in with `User=root` and
  `Group=root` (`systemctl edit gateon`).
- The ClamAV manager's `systemctl restart clamav-daemon` would need root, but it
  was already unreachable: it runs only after writing `/etc/clamav`, which
  `ProtectSystem=strict` refuses to root as well.
- Verified end to end on systemd 259: the packaged unit starts the real binary
  as `gateon` with exactly those three capabilities in its effective, ambient
  and bounding sets, serves `/healthz`, owns its state, and attaches eBPF at the
  TC hook of the default-route interface.
- The postinstall still runs on every upgrade and is idempotent; it no longer
  chowns anything to root.

## Alternatives considered

- **`DynamicUser=yes`.** No account to create, but the state moves under
  `/var/lib/private`, and a transient uid cannot own `/etc/gateon`, which gateon
  writes to at runtime.
- **Keep root and rely on the sandbox.** `ProtectSystem=strict` limits where
  root can write, not what root can do: load kernel modules, read every file,
  change any socket or process.
