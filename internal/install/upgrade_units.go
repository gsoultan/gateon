// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package install

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// The upgrade helper's units (ADR 0087), beside the gateway's.
const (
	upgradePathUnit        = "gateon-upgrade.path"
	upgradeServiceUnit     = "gateon-upgrade.service"
	upgradePathUnitPath    = "/lib/systemd/system/" + upgradePathUnit
	upgradeServiceUnitPath = "/lib/systemd/system/" + upgradeServiceUnit
	// upgradeRequest is the file the gateway leaves to ask for an install:
	// upgrade.SpoolName and upgrade.RequestFile under the state directory.
	upgradeRequest = "upgrade/request.json"
)

const upgradePathTemplate = `[Unit]
Description=Gateon - watch for an upgrade request
Documentation=https://github.com/gsoultan/gateon

[Path]
PathExists=%s/%s
Unit=` + upgradeServiceUnit + `

[Install]
WantedBy=multi-user.target
`

const upgradeServiceTemplate = `[Unit]
Description=Gateon - install a verified release
Documentation=https://github.com/gsoultan/gateon

[Service]
Type=oneshot
ExecStart=%s upgrade-helper --data-dir %s
EnvironmentFile=-/etc/default/gateon
StateDirectory=gateon-upgrade
StateDirectoryMode=0755
TimeoutStartSec=45min

# Root, and confined all the same: the helper writes the binary's directory,
# the gateway's state directory and its own, and has no use for a network.
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=%s -%s
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
PrivateNetwork=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX
SystemCallArchitectures=native
`

// renderUpgradePathUnit is the unit that starts the helper when the gateway
// leaves a request.
func renderUpgradePathUnit() string {
	return fmt.Sprintf(upgradePathTemplate, stateDir, upgradeRequest)
}

// renderUpgradeServiceUnit is the helper's unit for a binary at binPath. The
// helper replaces that binary by renaming over it, so the directory holding
// it is the path it must be able to write.
func renderUpgradeServiceUnit(binPath string) string {
	return fmt.Sprintf(upgradeServiceTemplate, binPath, stateDir, filepath.Dir(binPath), stateDir)
}

// installUpgradeUnits writes the helper's units and enables the watcher.
func installUpgradeUnits(binPath string) error {
	units := map[string]string{
		upgradePathUnitPath:    renderUpgradePathUnit(),
		upgradeServiceUnitPath: renderUpgradeServiceUnit(binPath),
	}
	for path, content := range units {
		// #nosec G306 -- systemd requires unit files to be world-readable.
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	if err := runCmd(exec.Command("systemctl", "daemon-reload")); err != nil {
		return err
	}
	return runCmd(exec.Command("systemctl", "enable", "--now", upgradePathUnit))
}

// uninstallUpgradeUnits stops the watcher and removes both units.
func uninstallUpgradeUnits() error {
	_ = exec.Command("systemctl", "disable", "--now", upgradePathUnit).Run()
	for _, path := range []string{upgradePathUnitPath, upgradeServiceUnitPath} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}
	return nil
}
