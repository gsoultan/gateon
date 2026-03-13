// Package l4 provides production-ready L4 (TCP/UDP) proxy with load balancing and health checks.
package l4

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// TCPBackendPool manages multiple TCP backends with health checks and load balancing.
type TCPBackendPool struct {
	addrs    []string
	policy   string // "round_robin", "least_conn"
	alive    []atomic.Bool
	active   []atomic.Int32
	next     atomic.Uint64
	interval time.Duration
	timeout  time.Duration
	mu       sync.RWMutex
	stop     chan struct{}
	stopOnce sync.Once
}

// NewTCPBackendPool creates a TCP backend pool with health checks.
func NewTCPBackendPool(addrs []string, policy string, intervalMs, timeoutMs int) *TCPBackendPool {
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
		addrs:    addrs,
		policy:   policy,
		alive:    make([]atomic.Bool, len(addrs)),
		active:   make([]atomic.Int32, len(addrs)),
		interval: time.Duration(intervalMs) * time.Millisecond,
		timeout:  time.Duration(timeoutMs) * time.Millisecond,
		stop:     make(chan struct{}),
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
