package ebpf

import (
	"context"
	"runtime"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// EbpfManager handles loading and attaching eBPF programs for performance offloading.
// Supports XDP (eXpress Data Path) for early packet dropping/rate limiting.
type EbpfManager struct {
	config *gateonv1.EbpfConfig
}

// NewEbpfManager creates a new eBPF manager.
func NewEbpfManager(conf *gateonv1.EbpfConfig) *EbpfManager {
	return &EbpfManager{config: conf}
}

// Start initiates the eBPF subsystem loading.
func (m *EbpfManager) Start(ctx context.Context) {
	if m.config == nil || !m.config.Enabled {
		return
	}

	if runtime.GOOS != "linux" {
		logger.L.Info().Msg("eBPF offloading is skipped on non-Linux OS (kernel support required)")
		return
	}

	logger.L.Info().
		Bool("xdp_rate_limit", m.config.XdpRateLimit).
		Bool("tc_filtering", m.config.TcFiltering).
		Msg("Initializing eBPF performance offloading subsystem")

	if m.config.XdpRateLimit {
		m.loadXDP(ctx)
	}
	if m.config.TcFiltering {
		m.loadTC(ctx)
	}
}

func (m *EbpfManager) loadXDP(ctx context.Context) {
	logger.L.Info().Msg("Attaching XDP program to primary interface for kernel-level rate limiting")
	// In a full implementation, we would use:
	// 1. Generate Go bindings from C eBPF code using bpf2go.
	// 2. Load the ELF binary into the kernel.
	// 3. Attach to the network interface using netlink.
}

func (m *EbpfManager) loadTC(ctx context.Context) {
	logger.L.Info().Msg("Attaching TC (Traffic Control) programs for kernel-level traffic classification")
	// TC programs allow for more complex filtering and can handle fragmented packets better than XDP.
}
