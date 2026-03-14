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
)

const systemdUnitTemplate = `[Unit]
Description=Gateon - API Gateway and Reverse Proxy
Documentation=https://github.com/gateon/gateon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=5s
WorkingDirectory=%s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=%s /var/lib/gateon

[Install]
WantedBy=multi-user.target
`

func installLinux(binPath string) error {
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return fmt.Errorf("run as root (sudo) to install: sudo gateon install")
	}

	content := fmt.Sprintf(systemdUnitTemplate, binPath, configDir, configDir)
	if err := os.WriteFile(systemdUnitPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write systemd unit: %w", err)
	}

	if err := os.MkdirAll(configDir, 0o755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create config dir %s: %w", configDir, err)
	}

	if err := runCmd(exec.Command("systemctl", "daemon-reload")); err != nil {
		return err
	}
	if err := runCmd(exec.Command("systemctl", "enable", "gateon")); err != nil {
		return err
	}
	if err := runCmd(exec.Command("systemctl", "start", "gateon")); err != nil {
		return err
	}

	fmt.Printf("Gateon installed as systemd service. Config dir: %s\n", configDir)
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
