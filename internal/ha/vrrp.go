// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ha

import (
	"context"
	"errors"
	"fmt"
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
	// localIP is this node's address on the HA interface, used to break a
	// priority tie deterministically.
	localIP net.IP
	// droppedAdverts counts datagrams rejected before they could influence the
	// election — wrong length, bad MAC or outside the replay window. A rising
	// count means either a misconfigured peer or someone probing the port.
	droppedAdverts atomic.Int64
	// runIP executes an `ip` invocation, or nil for the real one.
	//
	// The seam exists because the decision this package makes -- whether a node
	// may call itself MASTER -- cannot otherwise be tested anywhere the command
	// would really run. Gating on runtime.GOOS instead only moves the problem:
	// the assertions then pass on a developer's machine precisely because the
	// work was skipped, and fail on Linux CI where an unprivileged process has
	// no eth0 to add an address to.
	runIP func(args ...string) error
}

// ipCmd runs an `ip` invocation through the injected executor, or the real one.
func (m *HAManager) ipCmd(args ...string) error {
	if m.runIP != nil {
		return m.runIP(args...)
	}
	return defaultRunIP(args...)
}

// defaultRunIP executes `ip` on Linux and is a deliberate no-op elsewhere, so a
// developer machine can run the election without pretending to manage addresses.
func defaultRunIP(args ...string) error {
	if runtime.GOOS != "linux" {
		logger.L.LogInfo("VIP management (ip addr) is skipped on non-Linux OS")
		return nil
	}
	// #nosec G204 -- no shell is involved (exec.Command, not sh -c) and every
	// argument is validated by the caller, so `ip` receives an address and an
	// interface name or nothing at all.
	return exec.Command("ip", args...).Run()
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
	// Resolved once: the tie-break needs this per advert, and an interface
	// lookup on the receive path would be work an attacker could ask for.
	m.localIP = haInterfaceIP(m.config.Interface)

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
		if peerOutranks(priority, m.config.Priority, addr.IP, m.localIP) {
			m.lastSeen = time.Now()
			m.masterSeen = true
			if m.active {
				logger.L.LogInfo("Yielding MASTER status to a higher-ranked peer",
					"peer", addr.String(), "peer_prio", priority, "our_prio", m.config.Priority)
				m.releaseVIPs()
			}
		}
		// A peer we outrank is deliberately ignored, lastSeen included. Refreshing
		// it on their advert is what previously kept the better candidate from
		// ever taking over: it waited for a master that was never coming.
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
			// Only claim it if the address was actually taken. Setting active
			// regardless is how a misconfigured node came to advertise as
			// MASTER while holding nothing, silencing the peer that could have
			// held it.
			if err := m.acquireVIPs(); err != nil {
				logger.L.LogError("Staying BACKUP: cannot take the virtual IPs",
					"error", err)
			} else {
				m.active = true
			}
		}
	}

	// Always send advertisement if we are master
	if m.active {
		m.sendAdvert()
	}
}

func (m *HAManager) sendAdvert() {
	// Start opens the socket; without it there is nothing to write to and the
	// call below has no defined behaviour worth relying on.
	if m.udpConn == nil {
		return
	}

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

// acquireVIPs takes the virtual addresses, reporting whether this node can
// actually hold them.
//
// The answer matters more than it looks. An active node advertises, and every
// peer that receives an advert it does not outrank stays BACKUP -- so a node
// that marks itself MASTER without holding the address does not just fail, it
// suppresses the peer that would have succeeded. Nobody owns the VIP and every
// node reports itself healthy.
//
// Configuration is checked before the platform gate, deliberately: whether an
// interface name is nonsense does not depend on the operating system, and
// validating first is what makes this decision testable somewhere other than a
// Linux host with root.
func (m *HAManager) acquireVIPs() error {
	// A node with no virtual IPs configured has nothing to hold, and holding
	// nothing is not a false claim -- it is what the election looks like on its
	// own. The two-node verification harness relies on exactly this to separate
	// "who decides they are master" from "did ip addr add work".
	//
	// The defect this function guards is narrower and worth stating: claiming
	// MASTER while failing to acquire addresses that *were* configured. Nothing
	// was expected here, so nothing is missing.
	if len(m.config.VirtualIps) == 0 {
		logger.L.LogWarn("HA node has no virtual IPs configured; participating in " +
			"the election without managing any address")
		return nil
	}

	if m.config.Interface == "" {
		logger.L.LogWarn("No interface specified for HA VIPs")
		return errors.New("no interface specified")
	}

	if !validInterfaceName(m.config.Interface) {
		logger.L.LogError("Refusing to configure VIPs: invalid interface name",
			"interface", m.config.Interface)
		return fmt.Errorf("invalid interface name %q", m.config.Interface)
	}

	// A malformed address is dropped rather than fatal. Refusing the whole set
	// because one of several entries has a typo would turn a one-line
	// configuration mistake into a total loss of the service; what must not
	// happen is claiming MASTER while holding nothing at all, which is the
	// len(usable) == 0 case below.
	usable := make([]string, 0, len(m.config.VirtualIps))
	for _, vip := range m.config.VirtualIps {
		if !validVIP(vip) {
			logger.L.LogError("Refusing to add VIP: not an IP address or CIDR", "vip", vip)
			continue
		}
		usable = append(usable, vip)
	}
	if len(usable) == 0 {
		logger.L.LogWarn("No usable virtual IP configured for HA")
		return errors.New("no usable virtual IP configured")
	}

	var acquired int
	for _, vip := range usable {
		// Example: ip addr add 192.168.1.100/24 dev eth0
		if err := m.ipCmd("addr", "add", vip, "dev", m.config.Interface); err != nil {
			logger.L.LogError("Failed to add VIP to interface", "error", err, "vip", vip)
		} else {
			logger.L.LogInfo("Successfully acquired VIP", "vip", vip)
			acquired++
		}
	}
	if acquired == 0 {
		return errors.New("no virtual IP could be added to the interface")
	}
	return nil
}

// releaseVIPs gives up the virtual addresses and stops considering this node
// MASTER.
//
// The flag is cleared first and unconditionally. It records the intent to be
// master, and yielding to a higher-ranked peer is a decision that has already
// been made -- making it conditional on `ip addr del` succeeding meant a node
// that could not run the command kept advertising against the peer it had just
// yielded to, and, since step only acquires when !active, could never take the
// address back either.
func (m *HAManager) releaseVIPs() {
	if !m.active {
		return
	}
	m.active = false

	if !validInterfaceName(m.config.Interface) {
		logger.L.LogError("Cannot release VIPs: invalid interface name",
			"interface", m.config.Interface)
		return
	}

	for _, vip := range m.config.VirtualIps {
		if !validVIP(vip) {
			continue
		}
		if err := m.ipCmd("addr", "del", vip, "dev", m.config.Interface); err != nil {
			logger.L.LogError("Failed to release VIP", "error", err, "vip", vip)
		} else {
			logger.L.LogInfo("Successfully released VIP", "vip", vip)
		}
	}
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
