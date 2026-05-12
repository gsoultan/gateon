package security

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/robfig/cron/v3"
)

type ClamAVManager struct {
	config *gateonv1.ClamavConfig
	cron   *cron.Cron
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

	// Check if container already exists
	cmd := exec.CommandContext(ctx, "docker", "ps", "-a", "--filter", "name=gateon-clamav", "--format", "{{.Names}}")
	out, _ := cmd.Output()
	if strings.Contains(string(out), "gateon-clamav") {
		// Start it if it's stopped
		return exec.CommandContext(ctx, "docker", "start", "gateon-clamav").Run()
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

	return exec.CommandContext(ctx, "docker", args...).Run()
}

func (m *ClamAVManager) ensureLocal(ctx context.Context) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("local installation not supported on Windows, use Docker")
	}

	// Check if clamd is already installed
	if _, err := exec.LookPath("clamd"); err == nil {
		return nil
	}

	var cmd *exec.Cmd
	if _, err := exec.LookPath("apt-get"); err == nil {
		cmd = exec.CommandContext(ctx, "apt-get", "update", ";", "apt-get", "install", "-y", "clamav-daemon")
	} else if _, err := exec.LookPath("yum"); err == nil {
		cmd = exec.CommandContext(ctx, "yum", "install", "-y", "clamav", "clamav-update")
	} else if _, err := exec.LookPath("brew"); err == nil {
		cmd = exec.CommandContext(ctx, "brew", "install", "clamav")
	} else {
		return fmt.Errorf("no supported package manager found (apt, yum, brew)")
	}

	if err := cmd.Run(); err != nil {
		return err
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

func (m *ClamAVManager) RunFullScan(ctx context.Context) {
	logger.L.LogInfo("starting ClamAV full system scan")
	start := time.Now()

	// Use clamscan for full system scan (it's slower but doesn't require the daemon to be in memory if clamd is used for real-time)
	// Actually, if clamd is running, we should use clamdscan.

	binary := "clamscan"
	if _, err := exec.LookPath("clamdscan"); err == nil {
		binary = "clamdscan"
	}

	args := []string{"-r", "/"}
	if m.config.LowResourceMode {
		// Try to run with lower priority
		binary = "nice"
		args = append([]string{"-n", "19", "clamscan", "-r", "/"}, args...)
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	err := cmd.Run()
	if err != nil {
		logger.L.LogError("ClamAV full scan completed with errors or threats found", "error", err, "duration", time.Since(start))
	} else {
		logger.L.LogInfo("ClamAV full scan completed successfully", "duration", time.Since(start))
	}
}
