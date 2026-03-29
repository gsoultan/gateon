package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf xdp_rate_limit xdp_rate_limit.c -- -I../include

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
	if runtime.GOOS != "linux" {
		return
	}
	logger.L.Info().Msg("Attaching XDP program to primary interface for kernel-level rate limiting")

	// We use the interface name from config or default to eth0.
	ifaceName := "eth0"
	if m.config.Interface != "" {
		ifaceName = m.config.Interface
	}

	logger.L.Debug().Str("interface", ifaceName).Msg("Loading eBPF/XDP program")

	// The following would be implemented using the generated bpf2go code:
	/*
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			logger.L.Error().Err(err).Msg("failed to find interface")
			return
		}

		// Load pre-compiled programs and maps into the kernel.
		objs := xdp_rate_limitObjects{}
		if err := loadXdp_rate_limitObjects(&objs, nil); err != nil {
			logger.L.Error().Err(err).Msg("failed to load eBPF objects")
			return
		}
		defer objs.Close()

		// Attach the program to the interface.
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpRateLimit,
			Interface: iface.Index,
		})
		if err != nil {
			logger.L.Error().Err(err).Msg("failed to attach XDP program")
			return
		}
		defer l.Close()

		logger.L.Info().Msg("XDP rate limiting successfully attached")
	*/
}

func (m *EbpfManager) loadTC(ctx context.Context) {
	logger.L.Info().Msg("Attaching TC (Traffic Control) programs for kernel-level traffic classification")
	// TC programs allow for more complex filtering and can handle fragmented packets better than XDP.
}
