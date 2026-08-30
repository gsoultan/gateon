// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package install

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const serviceName = "gateon"

// Install installs Gateon as a system service.
// On Linux: writes systemd unit, enables and starts the service.
// On Windows: creates a service via sc.
func Install() error {
	binPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not determine executable path: %w", err)
	}
	binPath, err = filepath.EvalSymlinks(binPath)
	if err != nil {
		return fmt.Errorf("could not resolve executable path: %w", err)
	}

	switch runtime.GOOS {
	case "linux":
		return installLinux(binPath)
	case "windows":
		return installWindows(binPath)
	default:
		return fmt.Errorf("service install is not supported on %s", runtime.GOOS)
	}
}

// Uninstall removes the Gateon system service.
func Uninstall() error {
	switch runtime.GOOS {
	case "linux":
		return uninstallLinux()
	case "windows":
		return uninstallWindows()
	default:
		return fmt.Errorf("service uninstall is not supported on %s", runtime.GOOS)
	}
}

func runCmd(cmd *exec.Cmd) error {
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", cmd.String(), err)
	}
	return nil
}

const (
	systemdUnitPath = "/lib/systemd/system/gateon.service"
	configDir       = "/etc/gateon"
	stateDir        = "/var/lib/gateon"
)

const systemdUnitTemplate = `[Unit]
Description=Gateon - API Gateway and Reverse Proxy
Documentation=https://github.com/gateon/gateon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=%s
Restart=on-failure
RestartSec=5s
WorkingDirectory=%s
Environment=GLOBAL_CONFIG_FILE=%s/global.json

# State and config directories
StateDirectory=gateon
ConfigurationDirectory=gateon

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=-%s -%s

[Install]
WantedBy=multi-user.target
`

func installLinux(binPath string) error {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return fmt.Errorf("run as root (sudo) to install: sudo gateon install")
	}

	content := renderSystemdUnit(binPath)
	// #nosec G306 -- systemd requires unit files to be world-readable; 0600
	// makes the unit unloadable. This is the documented mode, not a default
	// nobody thought about.
	if err := os.WriteFile(systemdUnitPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write systemd unit: %w", err)
	}

	// 0750: the directory holds global.json, which carries database
	// credentials, the MaxMind licence key and SIEM tokens. The unit runs
	// User=root and the chown below makes it root:root, so nothing needs the
	// world bit that 0755 was granting every local account.
	// #nosec G302 -- a directory, not a file: the execute bit is what makes it
	// traversable, so 0750 is the tight mode here.
	if err := secureDir(configDir, 0o750); err != nil {
		return err
	}
	_ = exec.Command("chown", "-R", "root:root", configDir).Run()

	// #nosec G302 -- 0700 on a directory is already the tightest useful mode;
	// the execute bit is what makes it traversable by its owner.
	if err := secureDir(stateDir, 0o700); err != nil {
		return err
	}
	_ = exec.Command("chown", "-R", "root:root", stateDir).Run()

	if err := runCmd(exec.Command("systemctl", "daemon-reload")); err != nil {
		return err
	}
	if err := runCmd(exec.Command("systemctl", "enable", "gateon")); err != nil {
		return err
	}
	if err := runCmd(exec.Command("systemctl", "restart", "gateon")); err != nil {
		return err
	}

	fmt.Printf("Gateon installed as systemd service.\n")
	fmt.Printf("  Config dir: %s\n", configDir)
	fmt.Printf("  State dir:  %s\n", stateDir)
	fmt.Printf("  status: systemctl status gateon\n")
	fmt.Printf("  logs:   journalctl -u gateon -f\n")
	return nil
}

func uninstallLinux() error {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return fmt.Errorf("run as root (sudo) to uninstall: sudo gateon uninstall")
	}

	_ = exec.Command("systemctl", "stop", "gateon").Run()
	_ = exec.Command("systemctl", "disable", "gateon").Run()
	if err := runCmd(exec.Command("systemctl", "daemon-reload")); err != nil {
		return err
	}
	if err := os.Remove(systemdUnitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove systemd unit: %w", err)
	}
	fmt.Println("Gateon service uninstalled.")
	return nil
}

func installWindows(binPath string) error {
	// #nosec G204 -- binPath is os.Executable() resolved through EvalSymlinks,
	// i.e. this process's own path, not input. `gateon install` is an explicit
	// administrator action.
	cmd := exec.Command("sc", "create", serviceName, `binPath= "`+binPath+`"`, "start=", "auto")
	cmd.Stdout = nil
	cmd.Stderr = nil
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := string(out)
		if strings.Contains(msg, "1073") || strings.Contains(msg, "exists") {
			return fmt.Errorf("service already exists; run 'gateon uninstall' first")
		}
		if strings.Contains(msg, "Access is denied") || strings.Contains(msg, "740") {
			return fmt.Errorf("run as Administrator to install the service")
		}
		return fmt.Errorf("sc create: %w\n%s", err, msg)
	}
	fmt.Println("Gateon installed as Windows service.")
	fmt.Println("  Start: sc start gateon")
	fmt.Println("  Stop:  sc stop gateon")
	return nil
}

func uninstallWindows() error {
	_ = exec.Command("sc", "stop", serviceName).Run()
	cmd := exec.Command("sc", "delete", serviceName)
	cmd.Stdout = nil
	cmd.Stderr = nil
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := string(output)
		if strings.Contains(msg, "1060") || strings.Contains(msg, "does not exist") {
			fmt.Println("Gateon service was not installed.")
			return nil
		}
		if strings.Contains(msg, "Access is denied") {
			return fmt.Errorf("run as Administrator to uninstall the service")
		}
		return fmt.Errorf("sc delete: %w\n%s", err, msg)
	}
	fmt.Println("Gateon service uninstalled.")
	return nil
}

// renderSystemdUnit fills the unit template for a binary at binPath.
//
// Split out so the installer and its tests fill the template through the same
// call. The template takes five positional verbs, two of them inside
// ReadWritePaths, and a positional Sprintf that loses an argument does not fail
// -- it writes %!s(MISSING) into the unit. Landing that inside ProtectSystem's
// writable-path list produces a service that cannot write its own state, and
// systemd reports it as a permissions problem rather than a malformed unit.
func renderSystemdUnit(binPath string) string {
	return fmt.Sprintf(systemdUnitTemplate, binPath, stateDir, configDir, configDir, stateDir)
}

// secureDir creates dir if absent and forces it to mode, returning an error if
// it cannot.
//
// The chmod matters more than the mkdir and used to be the one whose error was
// discarded. MkdirAll succeeds silently on a directory that already exists, so
// an upgrade over an earlier install's 0755 /etc/gateon relied entirely on the
// chmod to remove the world bit -- and with `_ = os.Chmod(...)` a failure left
// global.json, which carries database credentials, the MaxMind licence key and
// SIEM tokens, readable by every local account while install reported success.
//
// An installer run under sudo by an administrator who can see the message is
// exactly the place to fail loudly instead.
func secureDir(dir string, mode os.FileMode) error {
	if err := os.MkdirAll(dir, mode); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		return fmt.Errorf("secure %s to %#o: %w", dir, mode, err)
	}
	return nil
}
