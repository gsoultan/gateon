// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ha

import (
	"context"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// HAManager handles Active-Passive failover using a simplified VRRP-like mechanism.
// It manages Virtual IPs (VIPs) on the local machine based on the cluster state.
type HAManager struct {
	config     *gateonv1.HaConfig
	active     bool
	lastSeen   time.Time
	mu         sync.RWMutex
	udpConn    *net.UDPConn
	masterSeen bool
	// droppedAdverts counts datagrams rejected before they could influence the
	// election — wrong length, bad MAC or outside the replay window. A rising
	// count means either a misconfigured peer or someone probing the port.
	droppedAdverts atomic.Int64
}

// DroppedAdverts reports how many heartbeats were rejected before they could
// affect VIP ownership.
func (m *HAManager) DroppedAdverts() int64 { return m.droppedAdverts.Load() }

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

	// Refuse to run unauthenticated. An advert is acted on by releasing a virtual
	// IP, so without a shared secret any host that can reach the port can take
	// the VIP away from the master with one datagram. Starting anyway would mean
	// the feature whose entire purpose is availability shipping its own remote
	// off switch. Failing closed costs HA until auth_pass is set; failing open
	// costs the VIP to whoever asks first.
	key := []byte(m.config.AuthPass)
	if len(key) == 0 {
		logger.L.LogError("Refusing to start High Availability: ha.auth_pass is empty. "+
			"Heartbeats would be unauthenticated, letting any host on the network force this "+
			"node to release its virtual IPs. Set ha.auth_pass to the same value on every node.",
			"vrid", m.config.VirtualRouterId)
		return
	}

	logger.L.LogInfo("High Availability Manager started",
		"vrid", m.config.VirtualRouterId,
		"priority", m.config.Priority,
		"vips", m.config.VirtualIps,
		"interface", m.config.Interface)

	// Set up UDP listener for heartbeats (VRRP uses 224.0.0.18, but we use a simpler UDP port for ease of deployment)
	// Default port: 8946
	addr, err := net.ResolveUDPAddr("udp", "224.0.0.18:8946")
	if err != nil {
		logger.L.LogError("Failed to resolve VRRP multicast address", "error", err)
		return
	}

	conn, err := net.ListenMulticastUDP("udp", nil, addr)
	if err != nil {
		// Fallback to unicast if multicast fails (e.g., in some cloud envs)
		logger.L.LogWarn("Multicast failed, falling back to unicast listener on 8946", "error", err)
		conn, err = net.ListenUDP("udp", &net.UDPAddr{Port: 8946})
		if err != nil {
			logger.L.LogError("Failed to start HA heartbeat listener", "error", err)
			return
		}
	}
	m.udpConn = conn
	defer m.udpConn.Close()

	// Election interval
	interval := time.Duration(m.config.AdvertInt) * time.Second
	if interval == 0 {
		interval = 1 * time.Second
	}

	m.mu.Lock()
	m.lastSeen = time.Now() // Wait at least 3 intervals before taking over
	m.mu.Unlock()

	// Go routine to listen for advertisements
	go m.listenLoop(ctx, key, replayWindow(interval))

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.L.LogInfo("HA Manager stopping, releasing resources")
			m.releaseVIPs()
			return
		case <-ticker.C:
			m.step(ctx)
		}
	}
}

func (m *HAManager) listenLoop(ctx context.Context, key []byte, window time.Duration) {
	buf := make([]byte, advertLen)
	for {
		_ = m.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := m.udpConn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}

		adv, err := parseAdvert(buf[:n], key, time.Now(), window)
		if err != nil {
			// Not logged per packet: an attacker controls the arrival rate, so
			// logging here would be a log-flood amplifier. The dropped-advert
			// counter is the signal an operator should watch.
			m.droppedAdverts.Add(1)
			continue
		}

		if adv.VRID != m.config.VirtualRouterId {
			continue
		}
		priority := adv.Priority

		m.mu.Lock()
		// If we see a higher priority node, or same priority with higher IP, it's the master
		if priority > m.config.Priority {
			m.lastSeen = time.Now()
			m.masterSeen = true
			if m.active {
				logger.L.LogInfo("Higher priority peer detected, yielding MASTER status", "peer", addr.String(), "peer_prio", priority)
				m.releaseVIPs()
			}
		} else if priority == m.config.Priority {
			// Tie-breaker: usually the node with higher IP wins
			// For simplicity here, we just accept the peer as master if it's already master
			m.lastSeen = time.Now()
			m.masterSeen = true
		}
		m.mu.Unlock()
	}
}

func (m *HAManager) step(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	interval := time.Duration(m.config.AdvertInt) * time.Second
	if interval == 0 {
		interval = 1 * time.Second
	}

	// If we haven't seen a master for 3 intervals, we become master
	if time.Since(m.lastSeen) > 3*interval {
		if !m.active {
			logger.L.LogInfo("No master detected, transitioning to MASTER state")
			m.acquireVIPs()
			m.active = true
		}
	}

	// Always send advertisement if we are master
	if m.active {
		m.sendAdvert()
	}
}

func (m *HAManager) sendAdvert() {
	addr, err := net.ResolveUDPAddr("udp", "224.0.0.18:8946")
	if err != nil {
		return
	}

	buf, err := encodeAdvert(advert{
		VRID:     m.config.VirtualRouterId,
		Priority: m.config.Priority,
		Sent:     time.Now(),
	}, []byte(m.config.AuthPass))
	if err != nil {
		// Start refuses to run without a key, so reaching here means the config
		// was swapped underneath us. Sending nothing is the safe response.
		return
	}

	// Send to multicast
	_, _ = m.udpConn.WriteToUDP(buf, addr)

	// Also send to 255.255.255.255 just in case
	baddr, err := net.ResolveUDPAddr("udp", "255.255.255.255:8946")
	if err == nil {
		_, _ = m.udpConn.WriteToUDP(buf, baddr)
	}
}

func (m *HAManager) acquireVIPs() {
	if runtime.GOOS != "linux" {
		logger.L.LogInfo("VIP management (ip addr) is skipped on non-Linux OS")
		return
	}

	if m.config.Interface == "" {
		logger.L.LogWarn("No interface specified for HA VIPs")
		return
	}

	if !validInterfaceName(m.config.Interface) {
		logger.L.LogError("Refusing to configure VIPs: invalid interface name",
			"interface", m.config.Interface)
		return
	}

	for _, vip := range m.config.VirtualIps {
		if !validVIP(vip) {
			logger.L.LogError("Refusing to add VIP: not an IP address or CIDR", "vip", vip)
			continue
		}
		// Example: ip addr add 192.168.1.100/24 dev eth0
		// #nosec G204 -- no shell is involved (exec.Command, not sh -c) and both
		// arguments are validated just above, so `ip` receives an address and an
		// interface name or nothing at all.
		cmd := exec.Command("ip", "addr", "add", vip, "dev", m.config.Interface)
		if err := cmd.Run(); err != nil {
			logger.L.LogError("Failed to add VIP to interface", "error", err, "vip", vip)
		} else {
			logger.L.LogInfo("Successfully acquired VIP", "vip", vip)
		}
	}
}

func (m *HAManager) releaseVIPs() {
	if runtime.GOOS != "linux" || !m.active {
		return
	}

	if !validInterfaceName(m.config.Interface) {
		return
	}

	for _, vip := range m.config.VirtualIps {
		if !validVIP(vip) {
			continue
		}
		// #nosec G204 -- see acquireVIPs: no shell, both arguments validated.
		cmd := exec.Command("ip", "addr", "del", vip, "dev", m.config.Interface)
		if err := cmd.Run(); err != nil {
			logger.L.LogError("Failed to release VIP", "error", err, "vip", vip)
		} else {
			logger.L.LogInfo("Successfully released VIP", "vip", vip)
		}
	}
	m.active = false
}

// HA configuration reaches this package from the management API, so the values
// handed to `ip` as root are settable by an authenticated administrator rather
// than baked into a file. exec.Command runs no shell, so this is not command
// injection — but validating means a typo fails loudly here instead of becoming
// an opaque `ip` error, and the surface handed to a privileged binary stays a
// shape we chose.

// validVIP reports whether s is a bare IP address or an IP in CIDR notation.
func validVIP(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// validInterfaceName reports whether s is plausibly a network interface name:
// non-empty, within the kernel's IFNAMSIZ limit, and free of separators or
// anything that could be read as an option.
func validInterfaceName(s string) bool {
	if s == "" || len(s) > 15 || strings.HasPrefix(s, "-") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-' || r == ':':
		default:
			return false
		}
	}
	return true
}
