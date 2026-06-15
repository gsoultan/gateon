package security

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	config       atomic.Pointer[gateonv1.ClamavConfig]
	cron         *cron.Cron
	status       ScanStatus
	mu           sync.Mutex
	isOverloaded func() bool
}

func NewClamAVManager(cfg *gateonv1.ClamavConfig) *ClamAVManager {
	m := &ClamAVManager{
		cron: cron.New(),
	}
	m.config.Store(cfg)
	m.isOverloaded = m.isSystemOverloaded
	return m
}

// cfg returns the current ClamAV configuration snapshot. It may be nil when
// ClamAV is not configured. The pointer is swapped atomically by Reconfigure,
// so each caller observes a consistent, immutable snapshot.
func (m *ClamAVManager) cfg() *gateonv1.ClamavConfig {
	return m.config.Load()
}

func (m *ClamAVManager) Start(ctx context.Context) error {
	c := m.cfg()
	if c == nil {
		return nil
	}

	if c.AutoInstall {
		go func() {
			if err := m.EnsureInstalled(context.Background()); err != nil {
				logger.L.LogError("failed to auto-install ClamAV", "error", err)
			}
		}()
	}

	m.mu.Lock()
	m.addSchedulesLocked(c)
	m.cron.Start()
	m.mu.Unlock()

	return nil
}

// addSchedulesLocked registers the configured cron jobs (full scan, database
// and application updates) on the current cron instance. Callers must hold m.mu.
func (m *ClamAVManager) addSchedulesLocked(c *gateonv1.ClamavConfig) {
	if c.FullScanSchedule != "" {
		_, err := m.cron.AddFunc(c.FullScanSchedule, func() {
			m.RunFullScan(context.Background())
		})
		if err != nil {
			logger.L.LogError("invalid ClamAV scan schedule", "error", err, "schedule", c.FullScanSchedule)
		} else {
			logger.L.LogInfo("scheduled ClamAV full scan", "schedule", c.FullScanSchedule)
		}
	}

	if c.DatabaseUpdateSchedule != "" {
		_, err := m.cron.AddFunc(c.DatabaseUpdateSchedule, func() {
			if err := m.UpdateDatabase(context.Background()); err != nil {
				logger.L.LogError("scheduled ClamAV database update failed", "error", err)
			}
		})
		if err != nil {
			logger.L.LogError("invalid ClamAV database update schedule", "error", err, "schedule", c.DatabaseUpdateSchedule)
		} else {
			logger.L.LogInfo("scheduled ClamAV database update", "schedule", c.DatabaseUpdateSchedule)
		}
	}

	if c.AppUpdateSchedule != "" {
		_, err := m.cron.AddFunc(c.AppUpdateSchedule, func() {
			if err := m.UpdateApplication(context.Background()); err != nil {
				logger.L.LogError("scheduled ClamAV application update failed", "error", err)
			}
		})
		if err != nil {
			logger.L.LogError("invalid ClamAV application update schedule", "error", err, "schedule", c.AppUpdateSchedule)
		} else {
			logger.L.LogInfo("scheduled ClamAV application update", "schedule", c.AppUpdateSchedule)
		}
	}
}

// Reconfigure atomically swaps the ClamAV configuration and rebuilds the
// scheduled jobs so changes take effect at runtime without recreating the
// manager or restarting the process. A nil cfg disables all scheduled jobs.
// It is safe for concurrent use.
func (m *ClamAVManager) Reconfigure(ctx context.Context, cfg *gateonv1.ClamavConfig) {
	m.config.Store(cfg)

	m.mu.Lock()
	m.cron.Stop()
	m.cron = cron.New()
	if cfg != nil {
		m.addSchedulesLocked(cfg)
	}
	m.cron.Start()
	m.mu.Unlock()

	if cfg != nil && cfg.AutoInstall {
		go func() {
			if err := m.EnsureInstalled(context.Background()); err != nil {
				logger.L.LogError("failed to auto-install ClamAV", "error", err)
			}
		}()
	}

	logger.L.LogInfo("ClamAV manager reconfigured", "enabled", cfg != nil)
}

func (m *ClamAVManager) Stop() {
	m.mu.Lock()
	m.cron.Stop()
	m.mu.Unlock()
}

func (m *ClamAVManager) IsInstalled(ctx context.Context) bool {
	c := m.cfg()
	if c == nil {
		return false
	}
	switch c.InstallationMode {
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

// Preflight validates that the prerequisites for the configured installation
// mode are satisfied without performing the (potentially multi-minute)
// installation. It lets callers surface actionable errors synchronously before
// kicking off a background install. A nil error means EnsureInstalled has a
// realistic chance of succeeding.
func (m *ClamAVManager) Preflight() error {
	c := m.cfg()
	if c == nil {
		return errors.New("ClamAV is not configured")
	}
	switch c.InstallationMode {
	case gateonv1.ClamavConfig_INSTALLATION_MODE_DOCKER:
		if _, err := exec.LookPath("docker"); err != nil {
			return errors.New("docker not found in PATH; install Docker or choose local installation mode")
		}
		return nil
	case gateonv1.ClamavConfig_INSTALLATION_MODE_LOCAL:
		if runtime.GOOS == "windows" {
			return errors.New("local installation is not supported on Windows; use Docker mode")
		}
		// Already present: no package manager required.
		for _, bin := range []string{"clamd", "clamscan", "clamdscan"} {
			if _, err := exec.LookPath(bin); err == nil {
				return nil
			}
		}
		return m.preflightLocalPackageManager()
	default:
		return errors.New("unsupported installation mode")
	}
}

// preflightLocalPackageManager verifies a supported package manager is present
// and that the process has the privileges that manager requires.
func (m *ClamAVManager) preflightLocalPackageManager() error {
	managers := []struct {
		bin       string
		needsRoot bool
	}{
		{"apt-get", true},
		{"yum", true},
		{"brew", false},
		{"apk", true},
	}
	for _, p := range managers {
		if _, err := exec.LookPath(p.bin); err != nil {
			continue
		}
		if p.needsRoot && os.Geteuid() != 0 {
			return fmt.Errorf("auto-installation with %s requires root privileges; run Gateon as root or pre-install ClamAV", p.bin)
		}
		return nil
	}
	return errors.New("no supported package manager found (apt, yum, brew, apk); pre-install ClamAV or use Docker mode")
}

func (m *ClamAVManager) EnsureInstalled(ctx context.Context) error {
	c := m.cfg()
	if c == nil {
		return nil
	}
	switch c.InstallationMode {
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
	c := m.cfg()
	image := ""
	if c != nil {
		image = c.DockerImage
	}
	if image == "" {
		image = "clamav/clamav:latest"
	}

	args := []string{"run", "-d", "--name", "gateon-clamav", "-p", "3310:3310"}
	if c != nil && c.LowResourceMode {
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
		if os.Geteuid() != 0 {
			return fmt.Errorf("auto-installation with apt-get requires root privileges. Please run Gateon as root or pre-install ClamAV")
		}
		// Update repository first
		updateCmd := exec.CommandContext(ctx, "apt-get", "update")
		updateCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		if out, err := updateCmd.CombinedOutput(); err != nil {
			logger.L.LogWarn("apt-get update failed", "error", err, "output", string(out))
		}

		cmd = exec.CommandContext(ctx, "apt-get", "install", "-y", "clamav-daemon", "clamav-freshclam")
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	} else if _, err := exec.LookPath("yum"); err == nil {
		if os.Geteuid() != 0 {
			return fmt.Errorf("auto-installation with yum requires root privileges. Please run Gateon as root or pre-install ClamAV")
		}
		cmd = exec.CommandContext(ctx, "yum", "install", "-y", "clamav", "clamav-update")
	} else if _, err := exec.LookPath("brew"); err == nil {
		cmd = exec.CommandContext(ctx, "brew", "install", "clamav")
	} else if _, err := exec.LookPath("apk"); err == nil {
		if os.Geteuid() != 0 {
			return fmt.Errorf("auto-installation with apk requires root privileges. Please run Gateon as root or pre-install ClamAV")
		}
		updateCmd := exec.CommandContext(ctx, "apk", "update")
		if out, err := updateCmd.CombinedOutput(); err != nil {
			logger.L.LogWarn("apk update failed", "error", err, "output", string(out))
		}
		cmd = exec.CommandContext(ctx, "apk", "add", "clamav", "clamav-daemon", "freshclam")
	} else {
		return fmt.Errorf("no supported package manager found (apt, yum, brew, apk)")
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		return m.formatExecError("installation", err, out)
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

	if c := m.cfg(); c != nil && c.LowResourceMode {
		m.tuneLocalClamav()
	}

	return nil
}

func (m *ClamAVManager) tuneLocalClamav() {
	if runtime.GOOS == "windows" {
		return
	}

	confPaths := []string{"/etc/clamav/clamd.conf", "/etc/clamd.d/scan.conf", "/usr/local/etc/clamd.conf"}
	var targetPath string
	for _, p := range confPaths {
		if _, err := os.Stat(p); err == nil {
			targetPath = p
			break
		}
	}

	if targetPath == "" {
		return
	}

	logger.L.LogInfo("tuning local ClamAV for low resource mode", "path", targetPath)

	data, err := os.ReadFile(targetPath)
	if err != nil {
		logger.L.LogWarn("could not read ClamAV config", "path", targetPath, "error", err)
		return
	}

	lines := strings.Split(string(data), "\n")
	settings := map[string]string{
		"ConcurrentScan":           "no",
		"MaxThreads":               "2",
		"MaxConnectionQueueLength": "5",
		"OnAccessMaxFileSize":      "5M",
	}

	modified := false
	for key, val := range settings {
		found := false
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, key+" ") || trimmed == key {
				lines[i] = fmt.Sprintf("%s %s", key, val)
				found = true
				modified = true
				break
			}
		}
		if !found {
			lines = append(lines, fmt.Sprintf("%s %s", key, val))
			modified = true
		}
	}

	if modified {
		err = os.WriteFile(targetPath, []byte(strings.Join(lines, "\n")), 0644)
		if err != nil {
			logger.L.LogWarn("could not write ClamAV config", "path", targetPath, "error", err)
		} else {
			logger.L.LogInfo("ClamAV configuration updated for low resource mode")
			// Try to restart clamd if it's running
			if _, err := exec.LookPath("systemctl"); err == nil {
				_ = exec.Command("systemctl", "restart", "clamav-daemon").Run()
			}
		}
	}
}

func (m *ClamAVManager) UpdateDatabase(ctx context.Context) error {
	logger.L.LogInfo("starting ClamAV database update")
	c := m.cfg()
	if c == nil {
		return fmt.Errorf("ClamAV is not configured")
	}
	switch c.InstallationMode {
	case gateonv1.ClamavConfig_INSTALLATION_MODE_DOCKER:
		// In docker, we can try to run freshclam inside the container
		cmd := exec.CommandContext(ctx, "docker", "exec", "gateon-clamav", "freshclam")
		if out, err := cmd.CombinedOutput(); err != nil {
			return m.formatExecError("docker freshclam", err, out)
		}
	case gateonv1.ClamavConfig_INSTALLATION_MODE_LOCAL:
		if _, err := exec.LookPath("freshclam"); err != nil {
			return fmt.Errorf("freshclam not found in PATH")
		}
		cmd := exec.CommandContext(ctx, "freshclam")
		if out, err := cmd.CombinedOutput(); err != nil {
			return m.formatExecError("local freshclam", err, out)
		}
	default:
		return fmt.Errorf("unsupported installation mode for database update")
	}
	logger.L.LogInfo("ClamAV database updated successfully")
	return nil
}

func (m *ClamAVManager) UpdateApplication(ctx context.Context) error {
	logger.L.LogInfo("starting ClamAV application update")
	c := m.cfg()
	if c == nil {
		return fmt.Errorf("ClamAV is not configured")
	}
	switch c.InstallationMode {
	case gateonv1.ClamavConfig_INSTALLATION_MODE_DOCKER:
		// Pull latest image and recreate container
		image := c.DockerImage
		if image == "" {
			image = "clamav/clamav:latest"
		}
		logger.L.LogInfo("pulling latest ClamAV image", "image", image)
		if out, err := exec.CommandContext(ctx, "docker", "pull", image).CombinedOutput(); err != nil {
			return m.formatExecError("docker pull", err, out)
		}

		// Remove old container
		logger.L.LogInfo("recreating ClamAV container")
		_ = exec.CommandContext(ctx, "docker", "stop", "gateon-clamav").Run()
		_ = exec.CommandContext(ctx, "docker", "rm", "gateon-clamav").Run()

		return m.ensureDocker(ctx)

	case gateonv1.ClamavConfig_INSTALLATION_MODE_LOCAL:
		// Use package manager to update
		var cmd *exec.Cmd
		if _, err := exec.LookPath("apt-get"); err == nil {
			cmd = exec.CommandContext(ctx, "apt-get", "install", "--only-upgrade", "-y", "clamav-daemon", "clamav-freshclam")
			cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		} else if _, err := exec.LookPath("yum"); err == nil {
			cmd = exec.CommandContext(ctx, "yum", "update", "-y", "clamav", "clamav-update")
		} else if _, err := exec.LookPath("brew"); err == nil {
			cmd = exec.CommandContext(ctx, "brew", "upgrade", "clamav")
		} else if _, err := exec.LookPath("apk"); err == nil {
			cmd = exec.CommandContext(ctx, "apk", "add", "--upgrade", "clamav", "clamav-daemon", "freshclam")
		} else {
			return fmt.Errorf("no supported package manager found for update")
		}

		if out, err := cmd.CombinedOutput(); err != nil {
			return m.formatExecError("application update", err, out)
		}

		// Restart services if systemctl is available
		if _, err := exec.LookPath("systemctl"); err == nil {
			_ = exec.CommandContext(ctx, "systemctl", "restart", "clamav-daemon").Run()
			_ = exec.CommandContext(ctx, "systemctl", "restart", "clamav-freshclam").Run()
		}

	default:
		return fmt.Errorf("unsupported installation mode for application update")
	}

	logger.L.LogInfo("ClamAV application updated successfully")
	return nil
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
				return m.formatExecError("initial freshclam", err, out)
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

func (m *ClamAVManager) isSystemOverloaded() bool {
	if runtime.GOOS == "windows" {
		return false
	}

	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return false
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return false
	}

	load1, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return false
	}

	// If load is greater than 2x number of CPUs, we consider it overloaded for a background scan
	return load1 > float64(runtime.NumCPU())*2.0
}

func (m *ClamAVManager) RunFullScan(ctx context.Context) {
	m.mu.Lock()
	if m.status.IsRunning {
		m.mu.Unlock()
		return
	}

	// Avoid starting a full scan if system load is too high
	if m.isOverloaded() {
		m.status.LastScan = time.Now()
		m.status.LastResult = "Skipped (High Load)"
		m.mu.Unlock()
		logger.L.LogWarn("skipping ClamAV full scan due to high system load")
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
	c := m.cfg()
	lowResource := c != nil && c.LowResourceMode

	// Ensure database is available before scanning
	if c != nil && c.InstallationMode == gateonv1.ClamavConfig_INSTALLATION_MODE_LOCAL {
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

	if lowResource {
		// Try to run with lower priority (CPU and I/O)
		if _, err := exec.LookPath("ionice"); err == nil {
			// -c 3 is the idle class: only gets I/O time when no other program has requested disk I/O
			fullArgs = append([]string{"-c", "3", "nice", "-n", "19", binary}, args...)
			execBinary = "ionice"
		} else if _, err := exec.LookPath("nice"); err == nil {
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
				if lowResource {
					if _, errIo := exec.LookPath("ionice"); errIo == nil {
						fullArgs = append([]string{"-c", "3", "nice", "-n", "19", binary}, args...)
						execBinary = "ionice"
					} else if _, errNice := exec.LookPath("nice"); errNice == nil {
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

func (m *ClamAVManager) formatExecError(ctx string, err error, out []byte) error {
	output := strings.TrimSpace(string(out))
	lowerOut := strings.ToLower(output)
	if strings.Contains(lowerOut, "read-only file system") {
		return fmt.Errorf("%s failed: filesystem is read-only. Please pre-install ClamAV or use Docker mode", ctx)
	}
	if strings.Contains(lowerOut, "permission denied") || strings.Contains(lowerOut, "root privileges") || strings.Contains(lowerOut, "are you root?") {
		return fmt.Errorf("%s failed: insufficient privileges. Please run Gateon as root or pre-install ClamAV", ctx)
	}

	// Truncate extremely long outputs
	if len(output) > 1000 {
		output = output[:1000] + "... (truncated)"
	}

	return fmt.Errorf("%s failed: %w (output: %s)", ctx, err, output)
}
