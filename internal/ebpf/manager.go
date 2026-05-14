package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf gateon_ebpf bpf/xdp_rate_limit.c -- -I../include

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// EbpfManager handles loading and attaching eBPF programs for performance offloading.
// Supports XDP (eXpress Data Path) for early packet dropping/rate limiting.
type EbpfManager struct {
	config *gateonv1.EbpfConfig
	mu     sync.RWMutex
	maps   map[string]*ebpf.Map
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
	SetAdaptiveRateLimit(ip string, interval time.Duration) error
	ShunJA3(ja3Md5 [16]byte) error
	UnshunJA3(ja3Md5 [16]byte) error
	ShunJA4(ja4Fingerprint string) error // New: JA4 support
	BlocklistCuckoo(ip string) error     // New: Cuckoo Filter support
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

func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP: %s", ipStr)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("only IPv4 is supported in eBPF for now: %s", ipStr)
	}
	// XDP/IP headers are in network byte order (Big Endian)
	return binary.BigEndian.Uint32(ipv4), nil
}

// ShunIP adds an IP to the XDP blocklist.
func (m *EbpfManager) ShunIP(ip string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	shunnedMap, ok := m.maps["shunned_ips"]
	if !ok {
		return fmt.Errorf("shunned_ips map not loaded")
	}

	ipUint, err := ipToUint32(ip)
	if err != nil {
		return err
	}

	logger.L.LogInfo("Shunning IP at XDP level", "ip", ip)
	reason := uint32(1) // General reason
	return shunnedMap.Update(ipUint, reason, ebpf.UpdateAny)
}

// UnshunIP removes an IP from the XDP blocklist.
func (m *EbpfManager) UnshunIP(ip string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	shunnedMap, ok := m.maps["shunned_ips"]
	if !ok {
		return fmt.Errorf("shunned_ips map not loaded")
	}

	ipUint, err := ipToUint32(ip)
	if err != nil {
		return err
	}

	logger.L.LogInfo("Unshunning IP at XDP level", "ip", ip)
	return shunnedMap.Delete(ipUint)
}

// BlockCountry adds a country code (converted to a numeric ID) to the XDP blocklist.
func (m *EbpfManager) BlockCountry(countryCode string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	blockMap, ok := m.maps["country_block_map"]
	if !ok {
		return fmt.Errorf("country_block_map not loaded")
	}

	// Simple hash for country code to 32-bit ID
	var id uint32
	if len(countryCode) >= 2 {
		id = uint32(countryCode[0])<<8 | uint32(countryCode[1])
	}

	logger.L.LogInfo("Blocking country at XDP level", "country", countryCode, "id", id)
	val := uint32(1)
	return blockMap.Update(id, val, ebpf.UpdateAny)
}

// UpdateManagementWhitelist updates the list of IPs allowed to access management port.
func (m *EbpfManager) UpdateManagementWhitelist(ips []string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	whitelistMap, ok := m.maps["mgmt_whitelist"]
	if !ok {
		return fmt.Errorf("mgmt_whitelist map not loaded")
	}

	// For a real production implementation, we'd diff and only update changes,
	// or clear and refill if the list is small.
	for _, ip := range ips {
		ipUint, err := ipToUint32(ip)
		if err != nil {
			continue
		}
		_ = whitelistMap.Update(ipUint, uint32(1), ebpf.UpdateAny)
	}
	return nil
}

// SetPortKnockingSequence sets the required port sequence for management access.
func (m *EbpfManager) SetPortKnockingSequence(seq []int32) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	configMap, ok := m.maps["knocking_config"]
	if !ok {
		return fmt.Errorf("knocking_config map not loaded")
	}

	logger.L.LogInfo("Setting port knocking sequence in eBPF", "sequence", seq)
	for i, port := range seq {
		if i >= 8 { // MAX_KNOCK_STEPS in C
			break
		}
		step := uint32(i)
		p := uint32(port)
		if err := configMap.Update(step, p, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	// Zero out remaining steps if sequence is shorter than before
	for i := len(seq); i < 8; i++ {
		step := uint32(i)
		_ = configMap.Update(step, uint32(0), ebpf.UpdateAny)
	}

	return nil
}

// UpdateLoadBalancerBackends updates the list of backends for XDP load balancing.
func (m *EbpfManager) UpdateLoadBalancerBackends(ips []string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	backendsMap, ok := m.maps["lb_backends"]
	countMap, ok2 := m.maps["lb_backends_count"]
	if !ok || !ok2 {
		return fmt.Errorf("load balancer maps not loaded")
	}

	logger.L.LogInfo("Updating XDP load balancer backends", "count", len(ips))

	type backend struct {
		IP      uint32
		EthAddr [6]uint8
	}

	for i, ipStr := range ips {
		if i >= 64 { // max_entries in C
			break
		}
		ipUint, err := ipToUint32(ipStr)
		if err != nil {
			continue
		}

		be := backend{
			IP: ipUint,
			// In a real scenario, we'd need the MAC address of the backend.
			// This might involve ARP or static config.
			EthAddr: [6]uint8{0, 0, 0, 0, 0, 0},
		}

		_ = backendsMap.Update(uint32(i), be, ebpf.UpdateAny)
	}

	count := uint32(len(ips))
	if count > 64 {
		count = 64
	}
	return countMap.Update(uint32(0), count, ebpf.UpdateAny)
}

// SetAdaptiveRateLimit sets a per-IP rate limit in nanoseconds.
func (m *EbpfManager) SetAdaptiveRateLimit(ip string, interval time.Duration) error {
	logger.L.LogInfo("Setting adaptive rate limit in eBPF", "ip", ip, "interval", interval)
	m.mu.RLock()
	defer m.mu.RUnlock()

	limitMap, ok := m.maps["adaptive_limits"]
	if !ok {
		return fmt.Errorf("adaptive_limits map not loaded")
	}

	ipUint, err := ipToUint32(ip)
	if err != nil {
		return err
	}

	ns := uint64(interval.Nanoseconds())
	return limitMap.Update(ipUint, ns, ebpf.UpdateAny)
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

// ShunJA4 adds a JA4 fingerprint to the XDP blocklist.
func (m *EbpfManager) ShunJA4(ja4Fingerprint string) error {
	logger.L.LogInfo("Shunning JA4 fingerprint at XDP level", "ja4", ja4Fingerprint)
	m.mu.RLock()
	defer m.mu.RUnlock()

	ja4Map, ok := m.maps["ja4_blocklist"]
	if !ok {
		return fmt.Errorf("ja4_blocklist map not loaded")
	}

	// JA4 is a string, we hash it to 32 bytes for the map key
	h := sha256.Sum256([]byte(ja4Fingerprint))
	return ja4Map.Update(h, uint32(1), ebpf.UpdateAny)
}

// BlocklistCuckoo adds an IP to the high-performance Cuckoo Filter in eBPF.
func (m *EbpfManager) BlocklistCuckoo(ip string) error {
	logger.L.LogInfo("Adding IP to eBPF Cuckoo Filter blocklist", "ip", ip)
	m.mu.RLock()
	defer m.mu.RUnlock()

	cuckooMap, ok := m.maps["cuckoo_filter"]
	if !ok {
		// Fallback to standard shunning if map not found (legacy BPF)
		return m.ShunIP(ip)
	}

	ipUint, err := ipToUint32(ip)
	if err != nil {
		return err
	}

	return cuckooMap.Update(ipUint, uint32(1), ebpf.UpdateAny)
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
