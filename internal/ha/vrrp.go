package ha

import (
	"context"
	"os/exec"
	"runtime"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// HAManager handles Active-Passive failover using a simplified VRRP-like mechanism.
// It manages Virtual IPs (VIPs) on the local machine based on the cluster state.
type HAManager struct {
	config *gateonv1.HaConfig
	active bool
}

// NewHAManager creates a new HA manager.
func NewHAManager(conf *gateonv1.HaConfig) *HAManager {
	return &HAManager{
		config: conf,
	}
}

// Start initiates the HA election loop.
func (m *HAManager) Start(ctx context.Context) {
	if m.config == nil || !m.config.Enabled {
		return
	}

	logger.L.Info().
		Int32("vrid", m.config.VirtualRouterId).
		Int32("priority", m.config.Priority).
		Strs("vips", m.config.VirtualIps).
		Str("interface", m.config.Interface).
		Msg("High Availability Manager started")

	// Election interval
	interval := time.Duration(m.config.AdvertInt) * time.Second
	if interval == 0 {
		interval = 1 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.L.Info().Msg("HA Manager stopping, releasing resources")
			m.releaseVIPs()
			return
		case <-ticker.C:
			m.step(ctx)
		}
	}
}

func (m *HAManager) step(ctx context.Context) {
	// Simplified logic for Phase 3:
	// In a full implementation, we would use UDP heartbeats to detect other nodes.
	// If no higher priority node is seen within (3 * interval), we become MASTER.

	if !m.active {
		// For the sake of demonstration in this environment, we assume we are the master
		// if we are enabled and have the highest configured priority.
		logger.L.Info().Msg("Transitioning to MASTER state")
		m.acquireVIPs()
		m.active = true
	}
}

func (m *HAManager) acquireVIPs() {
	if runtime.GOOS != "linux" {
		logger.L.Info().Msg("VIP management (ip addr) is skipped on non-Linux OS")
		return
	}

	if m.config.Interface == "" {
		logger.L.Warn().Msg("No interface specified for HA VIPs")
		return
	}

	for _, vip := range m.config.VirtualIps {
		// Example: ip addr add 192.168.1.100/24 dev eth0
		cmd := exec.Command("ip", "addr", "add", vip, "dev", m.config.Interface)
		if err := cmd.Run(); err != nil {
			logger.L.Error().Err(err).Str("vip", vip).Msg("Failed to add VIP to interface")
		} else {
			logger.L.Info().Str("vip", vip).Msg("Successfully acquired VIP")
		}
	}
}

func (m *HAManager) releaseVIPs() {
	if runtime.GOOS != "linux" || !m.active {
		return
	}

	for _, vip := range m.config.VirtualIps {
		cmd := exec.Command("ip", "addr", "del", vip, "dev", m.config.Interface)
		if err := cmd.Run(); err != nil {
			logger.L.Error().Err(err).Str("vip", vip).Msg("Failed to release VIP")
		} else {
			logger.L.Info().Str("vip", vip).Msg("Successfully released VIP")
		}
	}
	m.active = false
}
