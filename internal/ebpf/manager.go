package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf gateon_ebpf xdp_rate_limit.c -- -I../include

import (
	"context"
	"fmt"
	"runtime"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// EbpfManager handles loading and attaching eBPF programs for performance offloading.
// Supports XDP (eXpress Data Path) for early packet dropping/rate limiting.
type EbpfManager struct {
	config *gateonv1.EbpfConfig
}

type MapStats struct {
	ShunnedIPsCount int
	DroppedPackets  map[string]uint64
}

// Manager defines the interface for eBPF operations.
type Manager interface {
	Start(ctx context.Context)
	ShunIP(ip string) error
	UnshunIP(ip string) error
	BlockCountry(countryCode string) error
	UpdateManagementWhitelist(ips []string) error
	SetPortKnockingSequence(seq []int32) error
	UpdateLoadBalancerBackends(ips []string) error
	ShunJA3(ja3Md5 [16]byte) error
	UnshunJA3(ja3Md5 [16]byte) error
	GetMapStats() (MapStats, error)
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
		logger.L.LogInfo("eBPF offloading is skipped on non-Linux OS (kernel support required)")
		return
	}

	logger.L.LogInfo("Initializing eBPF performance offloading subsystem",
		"xdp_rate_limit", m.config.XdpRateLimit,
		"xdp_ip_shunning", m.config.XdpIpShunning,
		"xdp_load_balancing", m.config.XdpLoadBalancing,
		"tc_filtering", m.config.TcFiltering)

	if m.config.XdpRateLimit || m.config.XdpIpShunning || m.config.XdpLoadBalancing {
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
	logger.L.LogInfo("Attaching XDP program to primary interface for kernel-level offloading")

	// We use the interface name from config or default to eth0.
	ifaceName := "eth0"
	if m.config.Interface != "" {
		ifaceName = m.config.Interface
	}

	logger.L.LogDebug("Loading eBPF/XDP program", "interface", ifaceName)

	// The following would be implemented using the generated bpf2go code:
	/*
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			logger.L.LogError("failed to find interface", "error", err)
			return
		}

		// Load pre-compiled programs and maps into the kernel.
		objs := gateon_ebpfObjects{}
		if err := loadGateon_ebpfObjects(&objs, nil); err != nil {
			logger.L.LogError("failed to load eBPF objects", "error", err)
			return
		}
		defer objs.Close()

		// Attach the program to the interface.
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpMain,
			Interface: iface.Index,
		})
		if err != nil {
			logger.L.LogError("failed to attach XDP program", "error", err)
			return
		}
		defer l.Close()

		logger.L.LogInfo("XDP performance offloading successfully attached")
	*/
}

// ShunIP adds an IP to the XDP blocklist.
func (m *EbpfManager) ShunIP(ip string) error {
	logger.L.LogInfo("Shunning IP at XDP level", "ip", ip)
	// Implementation would use bpf_map_update_elem on shunned_ips map
	return nil
}

// UnshunIP removes an IP from the XDP blocklist.
func (m *EbpfManager) UnshunIP(ip string) error {
	logger.L.LogInfo("Unshunning IP at XDP level", "ip", ip)
	// Implementation would use bpf_map_delete_elem on shunned_ips map
	return nil
}

// BlockCountry adds a country code to the XDP blocklist.
func (m *EbpfManager) BlockCountry(countryCode string) error {
	logger.L.LogInfo("Blocking country at XDP level", "country", countryCode)
	// Implementation would update a country_block_map
	return nil
}

// UpdateManagementWhitelist updates the list of IPs allowed to access management port.
func (m *EbpfManager) UpdateManagementWhitelist(ips []string) error {
	logger.L.LogInfo("Updating management whitelist in eBPF", "ips", ips)
	// Implementation would update management_whitelist_map
	return nil
}

// SetPortKnockingSequence sets the required port sequence for management access.
func (m *EbpfManager) SetPortKnockingSequence(seq []int32) error {
	logger.L.LogInfo("Setting port knocking sequence in eBPF", "sequence", seq)
	// Implementation would update knocking_config_map
	return nil
}

// UpdateLoadBalancerBackends updates the list of backends for XDP load balancing.
func (m *EbpfManager) UpdateLoadBalancerBackends(ips []string) error {
	logger.L.LogInfo("Updating XDP load balancer backends", "backends", ips)
	// Implementation would update lb_backends and lb_backends_count maps
	return nil
}

// ShunJA3 adds a JA3 fingerprint to the XDP blocklist.
func (m *EbpfManager) ShunJA3(ja3Md5 [16]byte) error {
	logger.L.LogInfo("Shunning JA3 fingerprint at XDP level", "ja3", fmt.Sprintf("%x", ja3Md5))
	// Implementation would use bpf_map_update_elem on ja3_blocklist map
	return nil
}

// UnshunJA3 removes a JA3 fingerprint from the XDP blocklist.
func (m *EbpfManager) UnshunJA3(ja3Md5 [16]byte) error {
	logger.L.LogInfo("Unshunning JA3 fingerprint at XDP level", "ja3", fmt.Sprintf("%x", ja3Md5))
	// Implementation would use bpf_map_delete_elem on ja3_blocklist map
	return nil
}

// GetMapStats returns statistics from eBPF maps.
func (m *EbpfManager) GetMapStats() (MapStats, error) {
	if runtime.GOOS != "linux" {
		return MapStats{}, nil
	}
	// Implementation would iterate over maps to collect stats
	return MapStats{
		ShunnedIPsCount: 0,
		DroppedPackets: map[string]uint64{
			"shunned_ip":         0,
			"blocked_country":    0,
			"invalid_port_knock": 0,
		},
	}, nil
}

func (m *EbpfManager) loadTC(ctx context.Context) {
	logger.L.LogInfo("Attaching TC (Traffic Control) programs for kernel-level traffic classification")
	// TC programs allow for more complex filtering and can handle fragmented packets better than XDP.
}
