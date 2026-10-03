# Running Gateon as a Service

Gateon can run as a system service on Linux (systemd) and Windows.

## Built-in install command

You can install Gateon as a service directly:

```bash
# Linux (requires root)
sudo gateon install

# Windows (requires Administrator)
gateon install
```

To uninstall:

```bash
# Linux
sudo gateon uninstall

# Windows (as Administrator)
gateon uninstall
```

## Linux (systemd)

### From deb/rpm packages

Install the package built by [GoReleaser](https://github.com/gsoultan/gateon/releases):

```bash
# Debian/Ubuntu
sudo dpkg -i gateon_*_linux_amd64.deb

# RHEL/CentOS/Fedora
sudo rpm -i gateon_*_linux_amd64.rpm
```

Place config files (`global.json`, `routes.json`, etc.) in `/etc/gateon/`, then:

```bash
sudo systemctl start gateon
sudo systemctl enable gateon   # start on boot
```

A fresh install enables and starts the service. An upgrade leaves it as you had
it: a service you disabled stays disabled and a stopped one stays stopped (from
this release's package on; upgrading *from* v1.0.0 or earlier, whose scripts
stopped and disabled it on every upgrade, also comes out as you had it).

Secrets such as `GATEON_ENCRYPTION_KEY` go in `/etc/default/gateon`, `root:root`
and `0600`, which the unit reads -- not in an `Environment=` line, which any local
account can read with `systemctl show`. See
[backup-restore.md](backup-restore.md#the-encryption-key-is-not-in-the-backup).

### eBPF and HA need a drop-in

The unit grants only `CAP_NET_BIND_SERVICE`. eBPF and HA's virtual IP also need
`CAP_BPF` and `CAP_NET_ADMIN`; both features are off by default, and
`CAP_NET_ADMIN` is interface, route and firewall control, so the unit no longer
holds it for a gateway that does not use it. Before turning either on:

```bash
sudo mkdir -p /etc/systemd/system/gateon.service.d
sudo ln -s /usr/share/gateon/systemd/ebpf-ha.conf /etc/systemd/system/gateon.service.d/
sudo systemctl daemon-reload && sudo systemctl restart gateon
```

With `gateon install` or the tarball there is no `/usr/share/gateon`; run
`sudo systemctl edit gateon` and add the same lines
(`packaging/ebpf-ha.conf` in the repository):

```ini
[Service]
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN
LimitMEMLOCK=infinity
SystemCallFilter=bpf
```

Without them, enabling eBPF logs `eBPF is enabled but this process lacks the
capabilities to load it` with the missing ones, and the gateway runs without it.

### From archive (tar.gz)

1. Extract the release tarball.
2. Copy the systemd unit (from `packaging/gateon.service` in the repo):

   ```bash
   sudo cp packaging/gateon.service /lib/systemd/system/
   sudo systemctl daemon-reload
   ```

3. Copy the binary to `/usr/bin/gateon` (or adjust the unit).
4. Create `/etc/gateon` and `/var/lib/gateon`, then put your config files in `/etc/gateon`.
5. `sudo systemctl start gateon && sudo systemctl enable gateon`

## Windows

Use [WinSW](https://github.com/winsw/winsw/releases) to run Gateon as a Windows service.

1. Extract the release zip (e.g. `gateon_1.0.0_windows_amd64.zip`).
2. Download [WinSW](https://github.com/winsw/winsw/releases) and rename `winsw.exe` to `gateon-service.exe`.
3. Rename `gateon-service.xml` (from the archive) to match the exe stem — it should be `gateon-service.xml` next to `gateon-service.exe`.
4. Put `gateon-service.exe` and `gateon-service.xml` in the same folder as `gateon.exe`.
5. Open an elevated (Administrator) PowerShell:

   ```powershell
   .\gateon-service.exe install
   .\gateon-service.exe start
   ```

Place `global.json`, `routes.json`, etc. in the same folder as `gateon.exe` (the service working directory).
