package ha

import (
	"context"
	"encoding/binary"
	"net"
	"os/exec"
	"runtime"
	"sync"
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
	selfIP     string
	masterSeen bool
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

	// Set up UDP listener for heartbeats (VRRP uses 224.0.0.18, but we use a simpler UDP port for ease of deployment)
	// Default port: 8946
	addr, err := net.ResolveUDPAddr("udp", "224.0.0.18:8946")
	if err != nil {
		logger.L.Error().Err(err).Msg("Failed to resolve VRRP multicast address")
		return
	}

	conn, err := net.ListenMulticastUDP("udp", nil, addr)
	if err != nil {
		// Fallback to unicast if multicast fails (e.g., in some cloud envs)
		logger.L.Warn().Err(err).Msg("Multicast failed, falling back to unicast listener on 8946")
		conn, err = net.ListenUDP("udp", &net.UDPAddr{Port: 8946})
		if err != nil {
			logger.L.Error().Err(err).Msg("Failed to start HA heartbeat listener")
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
	go m.listenLoop(ctx)

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

func (m *HAManager) listenLoop(ctx context.Context) {
	buf := make([]byte, 64)
	for {
		m.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := m.udpConn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}

		if n < 8 {
			continue // Invalid packet
		}

		vrid := int32(binary.BigEndian.Uint32(buf[0:4]))
		priority := int32(binary.BigEndian.Uint32(buf[4:8]))

		if vrid != m.config.VirtualRouterId {
			continue
		}

		m.mu.Lock()
		// If we see a higher priority node, or same priority with higher IP, it's the master
		if priority > m.config.Priority {
			m.lastSeen = time.Now()
			m.masterSeen = true
			if m.active {
				logger.L.Info().Str("peer", addr.String()).Int32("peer_prio", priority).Msg("Higher priority peer detected, yielding MASTER status")
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
			logger.L.Info().Msg("No master detected, transitioning to MASTER state")
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

	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[0:4], uint32(m.config.VirtualRouterId))
	binary.BigEndian.PutUint32(buf[4:8], uint32(m.config.Priority))

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
