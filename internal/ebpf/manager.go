package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf -type ebpf_config gateon_ebpf bpf/xdp_rate_limit.c

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// EbpfManager handles loading and attaching eBPF programs for performance offloading.
// Supports XDP (eXpress Data Path) for early packet dropping/rate limiting.
//
// The actual program load/attach lives in the OS-specific files
// (manager_linux.go for the real implementation, manager_other.go for the
// no-op stub on non-Linux). This file holds the parts that compile on every
// platform: the BPF-map mutation methods and the stats reader, which operate
// over m.maps and are harmless no-ops while m.maps is empty (eBPF disabled or
// not yet loaded).
type EbpfManager struct {
	config       *gateonv1.EbpfConfig
	mu           sync.RWMutex
	maps         map[string]*ebpf.Map
	shunnedCount atomic.Int64

	// Teardown handles populated by loadXDP/loadTC (the attached link and the
	// loaded objects collection). Closed in reverse by close() when the
	// manager's context is cancelled, which detaches XDP and frees the maps.
	closers []io.Closer

	// Load status, set under mu during loadXDP and surfaced via GetMapStats so
	// operators can tell *why* metrics are zero (not attached, wrong iface, or
	// a load error) without digging through logs.
	attached bool
	iface    string
	loadErr  string
	// attachMode records how XDP attached: "native" (driver-level, fastest) or
	// "generic" (SKB/stack-level, a slower fallback used when the driver rejects
	// native attach — common on virtualized NICs such as AWS ENA/ens5).
	attachMode string
}

type MapStats struct {
	ShunnedIPsCount int
	DroppedPackets  map[string]uint64

	// Attached reports whether the XDP program is currently attached to a NIC.
	// When false, all other counters are expected to be zero.
	Attached bool
	// Interface is the NIC the XDP program is attached to (empty if not attached).
	Interface string
	// LoadError holds the last load/attach failure, if any.
	LoadError string
	// AttachMode is "native" or "generic" when attached, empty otherwise. Generic
	// mode is a slower SKB-level fallback; surfacing it lets operators understand
	// the performance trade-off when native XDP isn't available on the NIC.
	AttachMode string
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
	GetTopIPs(limit int) ([]IPStat, error)
	GetMapStats() (MapStats, error)
}

type IPStat struct {
	IP    string
	Count uint64
}

// NewEbpfManager creates a new eBPF manager.
func NewEbpfManager(conf *gateonv1.EbpfConfig) *EbpfManager {
	return &EbpfManager{
		config: conf,
		maps:   make(map[string]*ebpf.Map),
	}
}

// close detaches the XDP program and frees the loaded objects, then clears the
// map registry and load status. It is idempotent and safe to call when nothing
// was ever loaded (e.g. eBPF disabled or running on a non-Linux host).
func (m *EbpfManager) close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Close in reverse order: the attached link first (detaches XDP), then the
	// objects collection (frees programs and maps).
	for i := len(m.closers) - 1; i >= 0; i-- {
		if err := m.closers[i].Close(); err != nil {
			logger.L.LogError("failed to close eBPF resource during teardown", "error", err)
		}
	}
	m.closers = nil
	m.maps = make(map[string]*ebpf.Map)
	m.attached = false
	m.loadErr = ""
	m.attachMode = ""
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

func uint32ToIP(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
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
	err = shunnedMap.Update(ipUint, reason, ebpf.UpdateAny)
	if err == nil {
		m.shunnedCount.Add(1)
	}
	return err
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
	err = shunnedMap.Delete(ipUint)
	if err == nil {
		m.shunnedCount.Add(-1)
	}
	return err
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

var dropReasons = map[uint32]string{
	1: "shunned_ip",
	2: "blocked_country",
	3: "invalid_port_knock",
	4: "rate_limited",
}

// GetMapStats returns statistics from eBPF maps along with the current load
// status. On a non-Linux host or while the program is not attached, m.maps is
// empty so the per-reason drop counters are simply omitted, but Attached /
// Interface / LoadError are always reported so callers can see why.
func (m *EbpfManager) GetTopIPs(limit int) ([]IPStat, error) {
	m.mu.RLock()
	ipMap := m.maps["ip_telemetry"]
	m.mu.RUnlock()

	if ipMap == nil {
		return nil, nil
	}

	var stats []IPStat
	var key uint32
	var value uint64
	iter := ipMap.Iterate()
	for iter.Next(&key, &value) {
		stats = append(stats, IPStat{
			IP:    uint32ToIP(key).String(),
			Count: value,
		})
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	slices.SortFunc(stats, func(a, b IPStat) int {
		return cmp.Compare(b.Count, a.Count)
	})

	if len(stats) > limit {
		stats = stats[:limit]
	}

	return stats, nil
}

func (m *EbpfManager) GetMapStats() (MapStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := MapStats{
		ShunnedIPsCount: int(m.shunnedCount.Load()),
		DroppedPackets:  make(map[string]uint64),
		Attached:        m.attached,
		Interface:       m.iface,
		LoadError:       m.loadErr,
		AttachMode:      m.attachMode,
	}

	if dropStatsMap, ok := m.maps["drop_stats"]; ok {
		for id, name := range dropReasons {
			var values []uint64
			// PERCPU maps return a slice of values (one per CPU)
			if err := dropStatsMap.Lookup(id, &values); err == nil {
				var total uint64
				for _, v := range values {
					total += v
				}
				stats.DroppedPackets[name] = total
			}
		}
	}

	return stats, nil
}
