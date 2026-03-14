// Package l4 provides production-ready L4 (TCP/UDP) proxy with load balancing and health checks.
package l4

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TCPBackendPool manages multiple TCP backends with health checks and load balancing.
type TCPBackendPool struct {
	addrs          []string
	policy         string // "round_robin", "least_conn"
	alive          []atomic.Bool
	active         []atomic.Int32
	next           atomic.Uint64
	interval       time.Duration
	timeout        time.Duration
	proxyProtocol  bool // send HAProxy PROXY protocol v1 header before forwarding
	mu             sync.RWMutex
	stop           chan struct{}
	stopOnce       sync.Once
}

// NewTCPBackendPool creates a TCP backend pool with health checks.
// proxyProtocol: if true, sends HAProxy PROXY protocol v1 header so backend sees original client IP (e.g. for SPF).
func NewTCPBackendPool(addrs []string, policy string, intervalMs, timeoutMs int, proxyProtocol bool) *TCPBackendPool {
	if len(addrs) == 0 {
		return nil
	}
	if intervalMs <= 0 {
		intervalMs = 10000
	}
	if timeoutMs <= 0 {
		timeoutMs = 3000
	}
	if policy == "" {
		policy = "round_robin"
	}

	p := &TCPBackendPool{
		addrs:         addrs,
		policy:        policy,
		alive:         make([]atomic.Bool, len(addrs)),
		active:        make([]atomic.Int32, len(addrs)),
		interval:      time.Duration(intervalMs) * time.Millisecond,
		timeout:       time.Duration(timeoutMs) * time.Millisecond,
		proxyProtocol: proxyProtocol,
		stop:          make(chan struct{}),
	}
	for i := range addrs {
		p.alive[i].Store(true)
	}
	return p
}

// StartHealthChecks runs periodic TCP dial health checks. Call once.
func (p *TCPBackendPool) StartHealthChecks() {
	if p.interval <= 0 {
		return
	}
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			p.healthCheck()
		}
	}
}

func (p *TCPBackendPool) healthCheck() {
	for i, addr := range p.addrs {
		conn, err := net.DialTimeout("tcp", addr, p.timeout)
		if err != nil {
			p.alive[i].Store(false)
			continue
		}
		conn.Close()
		p.alive[i].Store(true)
	}
}

// Stop stops health checks. Safe to call multiple times.
func (p *TCPBackendPool) Stop() {
	p.stopOnce.Do(func() { close(p.stop) })
}

// Pick returns a backend address. Prefers alive backends. Returns "" if none available.
func (p *TCPBackendPool) Pick() string {
	p.mu.RLock()
	addrs := p.addrs
	alive := p.alive
	active := p.active
	policy := p.policy
	p.mu.RUnlock()

	if len(addrs) == 0 {
		return ""
	}

	switch policy {
	case "least_conn":
		var bestIdx int = -1
		var bestActive int32 = -1
		for i := range addrs {
			if !alive[i].Load() {
				continue
			}
			a := active[i].Load()
			if bestIdx < 0 || a < bestActive {
				bestIdx = i
				bestActive = a
			}
		}
		if bestIdx >= 0 {
			active[bestIdx].Add(1)
			return addrs[bestIdx]
		}
	default:
		n := uint64(len(addrs))
		for tries := uint64(0); tries < n; tries++ {
			idx := (p.next.Add(1) - 1) % n
			if alive[idx].Load() {
				active[idx].Add(1)
				return addrs[idx]
			}
		}
	}
	return ""
}

// Release decrements active count for the given address.
func (p *TCPBackendPool) Release(addr string) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for i, a := range p.addrs {
		if a == addr {
			p.active[i].Add(-1)
			return
		}
	}
}

// ProxyTCP proxies a client connection to a backend from the pool.
func (p *TCPBackendPool) ProxyTCP(ctx context.Context, client net.Conn) {
	addr := p.Pick()
	if addr == "" {
		_ = client.Close()
		return
	}
	defer p.Release(addr)

	dialer := net.Dialer{Timeout: 10 * time.Second}
	backend, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		_ = client.Close()
		return
	}
	defer backend.Close()

	if p.proxyProtocol {
		if err := writeProxyHeader(backend, client.RemoteAddr(), backend.RemoteAddr()); err != nil {
			_ = client.Close()
			return
		}
	}

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(backend, client)
		if c, ok := backend.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(client, backend)
	if c, ok := client.(interface{ CloseWrite() error }); ok {
		_ = c.CloseWrite()
	}
	<-done
}

// writeProxyHeader sends HAProxy PROXY protocol v1 header so the backend sees the original client IP.
// Format: "PROXY TCP4 src_ip dst_ip src_port dst_port\r\n" (or TCP6 for IPv6).
func writeProxyHeader(backend net.Conn, clientAddr, serverAddr net.Addr) error {
	srcIP, srcPort := parseAddr(clientAddr)
	dstIP, dstPort := parseAddr(serverAddr)
	if srcIP == nil || dstIP == nil {
		_, err := backend.Write([]byte("PROXY UNKNOWN\r\n"))
		return err
	}
	var family string
	if isIPv6(srcIP) || isIPv6(dstIP) {
		family = "TCP6"
	} else {
		family = "TCP4"
	}
	line := fmt.Sprintf("PROXY %s %s %s %s %s\r\n", family, srcIP.String(), dstIP.String(), srcPort, dstPort)
	_, err := backend.Write([]byte(line))
	return err
}

func parseAddr(addr net.Addr) (net.IP, string) {
	if addr == nil {
		return nil, "0"
	}
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, "0"
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip, port
}

func isIPv6(ip net.IP) bool {
	return ip != nil && ip.To4() == nil
}
