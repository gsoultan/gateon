// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf -type ebpf_config gateon_ebpf bpf/xdp_rate_limit.c

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
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
	// RL feedback handler (injected from internal/ai to avoid circular deps)
	rlFeedbackHandler func(ip string, score float64)
	// attachMode records how the program attached: "native" (driver-level, the
	// only mode that pays for itself), "generic" (SKB-level, opt-in only — see
	// allow_generic_xdp), or "tcx"/"clsact" for the TC ingress path.
	attachMode string
	// mgmtWhitelist is the set of mgmt_whitelist keys this manager last
	// installed *from configuration*, so UpdateManagementWhitelist can delete
	// the ones an operator removed. It deliberately excludes the entries the
	// XDP program writes itself when a source completes the port-knock
	// sequence: those are not config, and clearing the map wholesale would
	// revoke a live operator's knock every time unrelated settings were saved.
	// Bounded by mgmtWhitelistMax, which is the kernel map's own capacity.
	mgmtWhitelist map[uint32]struct{}
	// mgmtWhitelist6 is the same for the IPv6 allowlist, mgmt_whitelist6.
	mgmtWhitelist6 map[[16]byte]struct{}
}

// mgmtWhitelistMax mirrors max_entries on the mgmt_whitelist map in
// bpf/xdp_rate_limit.c. Entries past it cannot be installed, so tracking them
// would only grow the Go-side set without matching anything in the kernel.
const mgmtWhitelistMax = 1024

// lbBackendsMax mirrors max_entries on the lb_backends array in
// bpf/xdp_rate_limit.c.
const lbBackendsMax = 64

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
	// AttachMode is "native", "generic", "tcx" or "clsact" when attached, empty
	// otherwise. Anything other than "native" runs after the skb is allocated and
	// so drops no earlier than a firewall rule; surfacing the mode lets operators
	// see which trade-off they are actually running.
	AttachMode string
}

// Manager defines the interface for eBPF operations.
type Manager interface {
	Start(ctx context.Context)
	ShunIP(ip string) error
	UnshunIP(ip string) error
	UpdateManagementWhitelist(ips []string) error
	SetPortKnockingSequence(seq []int32) error
	UpdateLoadBalancerBackends(ips []string) error
	SetAdaptiveRateLimit(ip string, interval time.Duration) error
	ClearAdaptiveRateLimit(ip string) error
	ApplyRLFeedback(ip string, score float64) error
	SetRLFeedbackHandler(h func(ip string, score float64))
	RegisterPhantomPort(port uint32) error
	UnregisterPhantomPort(port uint32) error
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

// SetRLFeedbackHandler injects the reinforcement learning feedback processor.
func (m *EbpfManager) SetRLFeedbackHandler(h func(ip string, score float64)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rlFeedbackHandler = h
}

// ApplyRLFeedback forwards security feedback to the reinforcement learning agent.
func (m *EbpfManager) ApplyRLFeedback(ip string, score float64) error {
	m.mu.RLock()
	handler := m.rlFeedbackHandler
	m.mu.RUnlock()

	if handler != nil {
		handler(ip, score)
	}
	return nil
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
	// The mgmt_whitelist map went with the collection, so nothing this manager
	// installed from config is in the kernel any more. Keeping the set would
	// make the next update issue deletes for keys a fresh map never had.
	m.mgmtWhitelist = nil
	m.mgmtWhitelist6 = nil

	// The shunned map is gone with the objects above, so the count of what is in
	// it is zero. Leaving the counter alone survived a detach and reattach and
	// kept reporting entries that no longer existed anywhere -- into the security
	// posture report, the diagnostics screen and the ActiveShunnedEntitiesTotal
	// gauge, all of which read it. A metric that only ever drifts upward is worse
	// than no metric, because it is the one an operator checks to decide whether
	// mitigation is working.
	m.shunnedCount.Store(0)
}

// ipToUint32 encodes an IPv4 address as the key the programs look it up under:
// the source address exactly as it sits in the IPv4 header, four bytes in
// network order. cilium/ebpf marshals a uint32 key in the host's byte order, so
// the integer must be read from those bytes in the host's order too for them to
// reach the kernel unchanged. Reading them big-endian, as this used to, gave the
// address's numeric value -- which on a little-endian host (every EC2 instance)
// marshals reversed, so 1.2.3.4 was stored under 4.3.2.1 and every shun blocked
// an unrelated host while the attacker was never touched.
func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP: %s", ipStr)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("only IPv4 is supported in eBPF for now: %s", ipStr)
	}
	return binary.NativeEndian.Uint32(ipv4), nil
}

// uint32ToIP is the inverse: a key read back from a map, in host order, is the
// header bytes again.
func uint32ToIP(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, nn)
	return ip
}

// ShunIP adds an IP to the XDP blocklist: the address for IPv4, and for IPv6
// the /64 it sits in (see ipv6.go).
func (m *EbpfManager) ShunIP(ip string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	mapName, key, err := shunKey(ip)
	if err != nil {
		return err
	}
	shunnedMap, ok := m.maps[mapName]
	if !ok {
		return fmt.Errorf("%s map not loaded", mapName)
	}

	logger.L.LogInfo("Shunning IP at XDP level", "ip", ip, "map", mapName)
	reason := uint32(1) // General reason

	// UpdateNoExist rather than UpdateAny, so that "this is a new entry" and
	// "this was already shunned" are distinguishable. With UpdateAny both
	// succeeded and both incremented, so shunning the same address twice --
	// which is ordinary, since the same attacker trips the same rule again --
	// left the counter above the number of entries in the map, permanently.
	err = shunnedMap.Update(key, reason, ebpf.UpdateNoExist)
	switch {
	case err == nil:
		m.shunnedCount.Add(1)
		return nil
	case errors.Is(err, ebpf.ErrKeyExist):
		// Already shunned. The intent is satisfied, so this is not an error;
		// it is simply not a new entry.
		return nil
	default:
		return err
	}
}

// UnshunIP removes an IP from the XDP blocklist; for IPv6, the /64 it sits in.
func (m *EbpfManager) UnshunIP(ip string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	mapName, key, err := shunKey(ip)
	if err != nil {
		return err
	}
	shunnedMap, ok := m.maps[mapName]
	if !ok {
		return fmt.Errorf("%s map not loaded", mapName)
	}

	logger.L.LogInfo("Unshunning IP at XDP level", "ip", ip, "map", mapName)
	err = shunnedMap.Delete(key)
	if err == nil {
		m.shunnedCount.Add(-1)
	}
	return err
}

// whitelistKeys turns the configured addresses into map keys, one set per
// address family, dropping the entries that cannot be encoded -- a CIDR, a
// name -- and stopping each family at its kernel map's capacity. Sets, because
// the same address may legitimately appear twice in config.
func whitelistKeys(ips []string) allowlist {
	keys := allowlist{v4: map[uint32]struct{}{}, v6: map[[16]byte]struct{}{}}
	for _, s := range ips {
		ip, is4, err := parseAddress(s)
		if err != nil {
			logger.L.LogWarn("skipping an unusable management-whitelist entry", "ip", s, "error", err)
			continue
		}
		if is4 {
			addBounded(keys.v4, binary.NativeEndian.Uint32(ip), s)
			continue
		}
		addBounded(keys.v6, ipv6Key(ip), s)
	}
	return keys
}

// addBounded adds key to set unless the set is at the kernel map's capacity.
func addBounded[K comparable](set map[K]struct{}, key K, ip string) {
	if len(set) >= mgmtWhitelistMax {
		logger.L.LogWarn("management whitelist entry dropped at the kernel map's capacity",
			"max_entries", mgmtWhitelistMax, "ip", ip)
		return
	}
	set[key] = struct{}{}
}

// UpdateManagementWhitelist installs the configured set of IPs allowed to reach
// the management port, and removes the ones configuration no longer names.
//
// It used to only ever add. Deleting an address in the dashboard left it in the
// kernel map until the program was torn down, so a revoked administrator kept
// kernel-level access to the management port across every reload — the one
// place where "the config no longer says so" has to mean something.
//
// Clearing the map and refilling it would be wrong: the XDP program writes into
// the same map itself when a source completes the port-knock sequence, and that
// entry is what is holding the operator's own session open. So the manager
// remembers exactly what it installed from config and deletes only from that
// set; a knock-granted entry was never in it and survives. An address that is
// both configured and knock-granted is revoked when config drops it, which is
// the conservative reading of an operator deleting it.
func (m *EbpfManager) UpdateManagementWhitelist(ips []string) error {
	next := whitelistKeys(ips)

	m.mu.Lock()
	defer m.mu.Unlock()

	v4Map, ok4 := m.maps["mgmt_whitelist"]
	v6Map, ok6 := m.maps["mgmt_whitelist6"]
	if !ok4 || !ok6 {
		return fmt.Errorf("mgmt_whitelist maps not loaded")
	}

	// Track only what actually reached the kernel, so a later removal does not
	// try to delete a key that was never written.
	var err4, err6 error
	m.mgmtWhitelist, err4 = syncAllowlist(v4Map, m.mgmtWhitelist, next.v4, showIPv4Key, cmp.Compare[uint32])
	m.mgmtWhitelist6, err6 = syncAllowlist(v6Map, m.mgmtWhitelist6, next.v6, showIPv6Key, compareIPv6Keys)
	return cmp.Or(err4, err6)
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

// UpdateLoadBalancerBackends refuses to install backends for XDP load
// balancing, and forces the kernel-side backend count to zero.
//
// It used to accept them and write an all-zero destination MAC, because nothing
// in the tree resolves a backend's MAC — there is no ARP and no static MAC
// table. The XDP path then rewrote eth->h_dest to 00:00:00:00:00:00, rewrote
// iph->daddr without recomputing either the IPv4 or the L4 checksum, and
// returned XDP_TX: the redirected traffic went onto the wire addressed to
// nobody, and every request an operator pointed at this feature was silently
// destroyed. Accepting a setting and blackholing the traffic it names is worse
// than not having the setting, so this refuses instead, loudly and by name.
//
// The count is cleared *before* the refusal so a previously installed set stops
// being balanced even when this call goes on to fail: the XDP path reads
// lb_backends_count and does nothing at all while it is zero.
func (m *EbpfManager) UpdateLoadBalancerBackends(ips []string) error {
	m.mu.RLock()
	countMap, loaded := m.maps["lb_backends_count"]
	m.mu.RUnlock()

	if loaded {
		if err := countMap.Update(uint32(0), uint32(0), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clearing the XDP load balancer backend count: %w", err)
		}
	}

	if len(ips) == 0 {
		return nil
	}

	// Every backend offered here is unaddressable: the caller supplies IPs only,
	// and a destination MAC is not derivable from one. If MAC resolution ever
	// lands, this is the check it has to satisfy — refuse the entries it could
	// not resolve, install the rest, and only then set the count.
	refused := min(len(ips), lbBackendsMax)
	logger.L.LogError("refusing to enable XDP load balancing: no destination MAC can be resolved for "+
		"these backends, and the XDP path rewrites the destination MAC and returns XDP_TX, so the "+
		"redirected traffic would go onto the wire addressed to 00:00:00:00:00:00 with stale IPv4 "+
		"and L4 checksums and be silently lost. The kernel backend count is now 0, so nothing is "+
		"being redirected; turn this setting off and balance in the proxy instead.",
		"setting", "xdp_load_balancing", "backends", refused)
	return fmt.Errorf("xdp_load_balancing: refusing %d backend(s) with no resolved destination MAC; "+
		"XDP load balancing is not implemented and would blackhole the redirected traffic", refused)
}

// SetAdaptiveRateLimit sets a per-IP rate limit in nanoseconds.
func (m *EbpfManager) SetAdaptiveRateLimit(ip string, interval time.Duration) error {
	logger.L.LogInfo("Setting adaptive rate limit in eBPF", "ip", ip, "interval", interval)
	m.mu.RLock()
	defer m.mu.RUnlock()

	mapName, key, err := limitKey(ip)
	if err != nil {
		return err
	}
	limitMap, ok := m.maps[mapName]
	if !ok {
		return fmt.Errorf("%s map not loaded", mapName)
	}

	ns := uint64(interval.Nanoseconds())
	return limitMap.Update(key, ns, ebpf.UpdateAny)
}

// ClearAdaptiveRateLimit removes a per-IP adaptive rate limit.
//
// SetAdaptiveRateLimit had no inverse. Once an IP was throttled the entry
// stayed in the BPF map for the life of the process, so a false positive —
// a NAT gateway, a CI runner, a customer behind a corporate egress — was
// throttled to one packet per 10ms permanently, with no path back. Deleting
// the key is what lets a decayed threat score actually release the client, and
// it frees the map slot, which is a fixed resource: max_entries is set at load
// time and a full map starts rejecting new limits.
//
// A missing key is success, not an error: the caller wants the limit gone, and
// it already is.
func (m *EbpfManager) ClearAdaptiveRateLimit(ip string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	mapName, key, err := limitKey(ip)
	if err != nil {
		return err
	}
	limitMap, ok := m.maps[mapName]
	if !ok {
		return fmt.Errorf("%s map not loaded", mapName)
	}

	if err := limitMap.Delete(key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	}
	logger.L.LogInfo("Cleared adaptive rate limit in eBPF", "ip", ip)
	return nil
}

// RegisterPhantomPort enables AF_XDP redirection for a specific port.
func (m *EbpfManager) RegisterPhantomPort(port uint32) error {
	logger.L.LogInfo("Registering Phantom port in eBPF", "port", port)
	m.mu.RLock()
	defer m.mu.RUnlock()

	phantomMap, ok := m.maps["phantom_ports"]
	if !ok {
		return fmt.Errorf("phantom_ports map not loaded")
	}

	return phantomMap.Update(port, uint32(1), ebpf.UpdateAny)
}

// UnregisterPhantomPort disables AF_XDP redirection for a specific port.
func (m *EbpfManager) UnregisterPhantomPort(port uint32) error {
	logger.L.LogInfo("Unregistering Phantom port in eBPF", "port", port)
	m.mu.RLock()
	defer m.mu.RUnlock()

	phantomMap, ok := m.maps["phantom_ports"]
	if !ok {
		return fmt.Errorf("phantom_ports map not loaded")
	}

	return phantomMap.Delete(port)
}

var dropReasons = map[uint32]string{
	1: "shunned_ip",
	2: "blocked_country",
	3: "invalid_port_knock",
	4: "rate_limited",
	5: "syn_flood",
}

// GetMapStats returns statistics from eBPF maps along with the current load
// status. On a non-Linux host or while the program is not attached, m.maps is
// empty so the per-reason drop counters are simply omitted, but Attached /
// Interface / LoadError are always reported so callers can see why.
func (m *EbpfManager) GetTopIPs(limit int) ([]IPStat, error) {
	m.mu.RLock()
	ipMap := m.maps["ip_telemetry"]
	ipMap6 := m.maps["ip_telemetry6"]
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
	if ipMap6 != nil {
		var err error
		if stats, err = topIPv6(ipMap6, stats); err != nil {
			return nil, err
		}
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

// seedManagementWhitelist installs the configured management allowlist and
// reports how many addresses actually reached the kernel. It returns 0 when
// the feature is off, which is what keeps the kernel branch off with it.
//
// The count is the point. mgmt_whitelist is an exact-match IPv4 hash, and the
// programs read it as "if the allowlist is on, a packet to the management port
// whose source is absent is dropped". Switching that on against an empty map
// drops every management packet at the NIC, and the only way back is detaching
// the program -- which needs the access that was just refused. So the flag is
// only ever written after at least one address is in.
//
// ManagementConfig.AllowedIps is deliberately not the source: it is
// CIDR-capable and defaults to 0.0.0.0/0, and a __u32 key cannot express
// either. mgmt_whitelist_ips takes bare IPv4 addresses and says so.
func (m *EbpfManager) seedManagementWhitelist() int {
	if m.config == nil || !m.config.EnableMgmtWhitelist {
		return 0
	}
	if err := m.UpdateManagementWhitelist(m.config.MgmtWhitelistIps); err != nil {
		logger.L.LogError("failed to install the management whitelist", "error", err)
	}

	m.mu.RLock()
	installed := len(m.mgmtWhitelist) + len(m.mgmtWhitelist6)
	m.mu.RUnlock()

	if installed == 0 {
		logger.L.LogError("enable_mgmt_whitelist is on but no configured address could be installed, "+
			"so kernel-side management filtering stays off. Enabling it with an empty allowlist would "+
			"drop every packet to the management port at the NIC and lock you out, and detaching the "+
			"program needs the access it just refused. mgmt_whitelist_ips takes bare IPv4 and IPv6 "+
			"addresses; a CIDR cannot be expressed by these maps.",
			"setting", "enable_mgmt_whitelist", "configured", len(m.config.MgmtWhitelistIps))
	}
	return installed
}
