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

Install the package built by [GoReleaser](https://github.com/gateon/gateon/releases):

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

### From archive (tar.gz)

1. Extract the release tarball.
2. Copy the systemd unit (from `packaging/gateon.service` in the repo):

   ```bash
   sudo cp packaging/gateon.service /lib/systemd/system/
   sudo systemctl daemon-reload
   ```

3. Copy the binary to `/usr/bin/gateon` (or adjust the unit).
4. Create `/etc/gateon`, put your config files there.
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
