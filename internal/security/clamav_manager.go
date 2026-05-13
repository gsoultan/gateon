package security

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/robfig/cron/v3"
)

type ScanStatus struct {
	IsRunning  bool      `json:"is_running"`
	LastScan   time.Time `json:"last_scan,omitzero"`
	LastError  string    `json:"last_error,omitzero"`
	LastResult string    `json:"last_result,omitzero"`
}

type ClamAVManager struct {
	config *gateonv1.ClamavConfig
	cron   *cron.Cron
	status ScanStatus
	mu     sync.Mutex
}

func NewClamAVManager(cfg *gateonv1.ClamavConfig) *ClamAVManager {
	return &ClamAVManager{
		config: cfg,
		cron:   cron.New(),
	}
}

func (m *ClamAVManager) Start(ctx context.Context) error {
	if m.config == nil {
		return nil
	}

	if m.config.AutoInstall {
		go func() {
			if err := m.EnsureInstalled(context.Background()); err != nil {
				logger.L.LogError("failed to auto-install ClamAV", "error", err)
			}
		}()
	}

	if m.config.FullScanSchedule != "" {
		_, err := m.cron.AddFunc(m.config.FullScanSchedule, func() {
			m.RunFullScan(context.Background())
		})
		if err != nil {
			logger.L.LogError("invalid ClamAV scan schedule", "error", err, "schedule", m.config.FullScanSchedule)
		} else {
			m.cron.Start()
			logger.L.LogInfo("scheduled ClamAV full scan", "schedule", m.config.FullScanSchedule)
		}
	}

	return nil
}

func (m *ClamAVManager) Stop() {
	m.cron.Stop()
}

func (m *ClamAVManager) IsInstalled(ctx context.Context) bool {
	if m.config == nil {
		return false
	}
	switch m.config.InstallationMode {
	case gateonv1.ClamavConfig_INSTALLATION_MODE_DOCKER:
		if _, err := exec.LookPath("docker"); err != nil {
			return false
		}
		// Match exact name and only show running containers
		cmd := exec.CommandContext(ctx, "docker", "ps", "--filter", "name=^/gateon-clamav$", "--format", "{{.Names}}")
		out, _ := cmd.Output()
		return strings.TrimSpace(string(out)) == "gateon-clamav"
	case gateonv1.ClamavConfig_INSTALLATION_MODE_LOCAL:
		// Check for multiple possible binaries
		binaries := []string{"clamd", "clamscan", "clamdscan"}
		for _, bin := range binaries {
			if _, err := exec.LookPath(bin); err == nil {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func (m *ClamAVManager) EnsureInstalled(ctx context.Context) error {
	switch m.config.InstallationMode {
	case gateonv1.ClamavConfig_INSTALLATION_MODE_DOCKER:
		return m.ensureDocker(ctx)
	case gateonv1.ClamavConfig_INSTALLATION_MODE_LOCAL:
		return m.ensureLocal(ctx)
	default:
		return nil
	}
}

func (m *ClamAVManager) ensureDocker(ctx context.Context) error {
	// Check if docker is installed
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found in PATH")
	}

	// Check if container already exists (exact match)
	cmd := exec.CommandContext(ctx, "docker", "ps", "-a", "--filter", "name=^/gateon-clamav$", "--format", "{{.Names}}")
	out, err := cmd.CombinedOutput()
	if err == nil && strings.TrimSpace(string(out)) == "gateon-clamav" {
		// Start it if it's stopped
		if startOut, err := exec.CommandContext(ctx, "docker", "start", "gateon-clamav").CombinedOutput(); err != nil {
			return fmt.Errorf("failed to start existing ClamAV container: %w (output: %s)", err, strings.TrimSpace(string(startOut)))
		}
		return nil
	}

	// Pull and run
	image := m.config.DockerImage
	if image == "" {
		image = "clamav/clamav:latest"
	}

	args := []string{"run", "-d", "--name", "gateon-clamav", "-p", "3310:3310"}
	if m.config.LowResourceMode {
		// Limit memory to 1GB and 0.5 CPU if possible (Docker limits)
		// Note: ClamAV really needs ~1GB to even start.
		args = append(args, "--memory=1g", "--cpus=0.5")
	}
	args = append(args, image)

	if runOut, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to run ClamAV container: %w (output: %s)", err, strings.TrimSpace(string(runOut)))
	}
	return nil
}

func (m *ClamAVManager) ensureLocal(ctx context.Context) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("local installation not supported on Windows, use Docker")
	}

	// Check if clamd is already installed
	if _, err := exec.LookPath("clamd"); err == nil {
		_ = m.ensureDatabase(ctx)
		return nil
	}

	var cmd *exec.Cmd
	if _, err := exec.LookPath("apt-get"); err == nil {
		// Update repository first
		updateCmd := exec.CommandContext(ctx, "apt-get", "update")
		updateCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		if out, err := updateCmd.CombinedOutput(); err != nil {
			logger.L.LogWarn("apt-get update failed", "error", err, "output", string(out))
		}

		cmd = exec.CommandContext(ctx, "apt-get", "install", "-y", "clamav-daemon", "clamav-freshclam")
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	} else if _, err := exec.LookPath("yum"); err == nil {
		cmd = exec.CommandContext(ctx, "yum", "install", "-y", "clamav", "clamav-update")
	} else if _, err := exec.LookPath("brew"); err == nil {
		cmd = exec.CommandContext(ctx, "brew", "install", "clamav")
	} else if _, err := exec.LookPath("apk"); err == nil {
		updateCmd := exec.CommandContext(ctx, "apk", "update")
		if out, err := updateCmd.CombinedOutput(); err != nil {
			logger.L.LogWarn("apk update failed", "error", err, "output", string(out))
		}
		cmd = exec.CommandContext(ctx, "apk", "add", "clamav", "clamav-daemon", "freshclam")
	} else {
		return fmt.Errorf("no supported package manager found (apt, yum, brew, apk)")
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("installation failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	// Try to enable and start services if systemctl is available
	if _, err := exec.LookPath("systemctl"); err == nil {
		// We don't return error here because the installation itself succeeded,
		// and some environments might not have systemd even if systemctl is present (rare but possible).
		_ = exec.CommandContext(ctx, "systemctl", "enable", "--now", "clamav-daemon").Run()
		_ = exec.CommandContext(ctx, "systemctl", "enable", "--now", "clamav-freshclam").Run()
	}

	// Ensure database exists, otherwise clamscan will fail with status 2
	if err := m.ensureDatabase(ctx); err != nil {
		logger.L.LogWarn("could not ensure ClamAV database", "error", err)
	}

	if m.config.LowResourceMode {
		m.tuneLocalClamav()
	}

	return nil
}

func (m *ClamAVManager) tuneLocalClamav() {
	// Implementation would involve editing /etc/clamav/clamd.conf
	// For now, we'll just log that we would tune it.
	logger.L.LogInfo("tuning local ClamAV for low resource mode (logic to be implemented for specific OS)")
}

func (m *ClamAVManager) ensureDatabase(ctx context.Context) error {
	// Check common database locations
	dbPaths := []string{
		"/var/lib/clamav/main.cvd",
		"/var/lib/clamav/main.cld",
		"/var/lib/clamav/daily.cvd",
		"/var/lib/clamav/daily.cld",
		"/usr/local/share/clamav/main.cvd",
		"/usr/local/share/clamav/main.cld",
	}

	found := false
	for _, path := range dbPaths {
		if _, err := os.Stat(path); err == nil {
			found = true
			break
		}
	}

	if !found {
		logger.L.LogInfo("ClamAV database not found, running freshclam...")
		if _, err := exec.LookPath("freshclam"); err == nil {
			// This might take a while, but we run it in background or at least try it once.
			// We use a shorter timeout for the initial check to not block too long.
			freshCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			defer cancel()
			if out, err := exec.CommandContext(freshCtx, "freshclam").CombinedOutput(); err != nil {
				return fmt.Errorf("initial freshclam failed: %w (output: %s)", err, string(out))
			}
			logger.L.LogInfo("ClamAV database updated successfully")
		} else {
			return errors.New("freshclam not found, cannot download ClamAV database")
		}
	}
	return nil
}

func (m *ClamAVManager) GetScanStatus() ScanStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *ClamAVManager) RunFullScan(ctx context.Context) {
	m.mu.Lock()
	if m.status.IsRunning {
		m.mu.Unlock()
		return
	}
	m.status.IsRunning = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.status.IsRunning = false
		m.status.LastScan = time.Now()
		m.mu.Unlock()
	}()

	logger.L.LogInfo("starting ClamAV full system scan")
	start := time.Now()

	// Ensure database is available before scanning
	if m.config.InstallationMode == gateonv1.ClamavConfig_INSTALLATION_MODE_LOCAL {
		if err := m.ensureDatabase(ctx); err != nil {
			logger.L.LogError("ClamAV database not available, aborting scan", "error", err)
			m.mu.Lock()
			m.status.LastError = err.Error()
			m.status.LastResult = "Database missing"
			m.mu.Unlock()
			return
		}
	}

	binary := "clamscan"
	hasClamdscan := false
	if _, err := exec.LookPath("clamdscan"); err == nil {
		binary = "clamdscan"
		hasClamdscan = true
	}

	target := "/"
	if runtime.GOOS == "windows" {
		target = "C:\\"
	}

	args := []string{"-r", target}
	fullArgs := args
	execBinary := binary

	if m.config.LowResourceMode {
		// Try to run with lower priority
		if _, err := exec.LookPath("nice"); err == nil {
			fullArgs = append([]string{"-n", "19", binary}, args...)
			execBinary = "nice"
		}
	}

	cmd := exec.CommandContext(ctx, execBinary, fullArgs...)
	out, err := cmd.CombinedOutput()

	// If clamdscan failed with error, try falling back to clamscan
	if err != nil && hasClamdscan && binary == "clamdscan" {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok && exitErr.ExitCode() == 2 {
			if _, errScan := exec.LookPath("clamscan"); errScan == nil {
				logger.L.LogInfo("clamdscan failed (possibly daemon not running), falling back to clamscan")
				binary = "clamscan"
				execBinary = binary
				fullArgs = args
				if m.config.LowResourceMode {
					if _, errNice := exec.LookPath("nice"); errNice == nil {
						fullArgs = append([]string{"-n", "19", binary}, args...)
						execBinary = "nice"
					}
				}
				cmd = exec.CommandContext(ctx, execBinary, fullArgs...)
				out, err = cmd.CombinedOutput()
			}
		}
	}

	m.mu.Lock()
	if err != nil {
		// clamscan returns 1 if viruses are found, 2 if an error occurred
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok && exitErr.ExitCode() == 1 {
			m.status.LastError = ""
			m.status.LastResult = "Threats found"
			logger.L.LogWarn("ClamAV full scan found threats", "duration", time.Since(start))
		} else {
			output := strings.TrimSpace(string(out))
			m.status.LastError = fmt.Sprintf("%v: %s", err, output)
			m.status.LastResult = "Error occurred"
			logger.L.LogError("ClamAV full scan failed", "error", err, "output", output, "duration", time.Since(start))
		}
	} else {
		m.status.LastError = ""
		m.status.LastResult = "Clean"
		logger.L.LogInfo("ClamAV full scan completed successfully", "duration", time.Since(start))
	}
	m.mu.Unlock()
}
