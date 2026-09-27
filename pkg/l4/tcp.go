// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

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

	"github.com/gsoultan/gateon/internal/logger"
)

// TCPBackendPool manages multiple TCP backends with health checks and load balancing.
type TCPBackendPool struct {
	addrs  []string
	policy string // "round_robin", "least_conn"
	alive  []atomic.Bool
	active []atomic.Int32
	// Consecutive health-check results, so a single blip cannot change a
	// backend's state. Only the counter that could still change state is
	// incremented, which keeps both bounded.
	fails         []atomic.Int32
	successes     []atomic.Int32
	next          atomic.Uint64
	interval      time.Duration
	timeout       time.Duration
	proxyProtocol bool // send HAProxy PROXY protocol v1 header before forwarding
	mu            sync.RWMutex
	stop          chan struct{}
	stopOnce      sync.Once
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
		fails:         make([]atomic.Int32, len(addrs)),
		successes:     make([]atomic.Int32, len(addrs)),
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

// Health-check thresholds. A single dial result used to flip a backend's state
// outright, which is wrong in both directions: one transient timeout -- a GC
// pause, a brief network blip -- evicted a healthy backend, and one successful
// dial returned a struggling one to service. A TCP connect also says nothing
// about whether the application behind it is ready, so recovery in particular
// should not be believed on first sight.
//
// Down takes more evidence than up on purpose: removing capacity from a pool is
// the more disruptive direction when the pool is small.
const (
	tcpFailThreshold = 3
	tcpRiseThreshold = 2
)

func (p *TCPBackendPool) healthCheck() {
	for i, addr := range p.addrs {
		conn, err := net.DialTimeout("tcp", addr, p.timeout)
		if err != nil {
			p.recordFailure(i, addr, err)
			continue
		}
		_ = conn.Close()
		p.recordSuccess(i, addr)
	}
}

// recordFailure counts a failed check, marking the backend down only once the
// failures are consecutive enough to mean something.
func (p *TCPBackendPool) recordFailure(i int, addr string, cause error) {
	p.successes[i].Store(0)
	if !p.alive[i].Load() {
		return // already down; nothing further to count toward
	}
	if p.fails[i].Add(1) >= tcpFailThreshold {
		p.alive[i].Store(false)
		p.fails[i].Store(0)
		logger.L.LogWarn("L4 backend marked down after consecutive failed health checks",
			"addr", addr, "consecutive_failures", tcpFailThreshold, "error", cause)
	}
}

// recordSuccess counts a passing check, restoring the backend only once it has
// held up across more than one interval.
func (p *TCPBackendPool) recordSuccess(i int, addr string) {
	p.fails[i].Store(0)
	if p.alive[i].Load() {
		return // already up
	}
	if p.successes[i].Add(1) >= tcpRiseThreshold {
		p.alive[i].Store(true)
		p.successes[i].Store(0)
		logger.L.LogInfo("L4 backend restored after consecutive successful health checks",
			"addr", addr, "consecutive_successes", tcpRiseThreshold)
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

	aliveCount := 0
	for i := range alive {
		if alive[i].Load() {
			aliveCount++
		}
	}
	if aliveCount == 0 {
		return ""
	}

	switch policy {
	case "least_conn":
		var bestIdx = -1
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
	// The client socket belongs to this call: the error paths below close it
	// explicitly, and the normal path only half-closed it, leaving the
	// descriptor to the garbage collector. The plaintext entrypoint that hands
	// connections here does not close them either, so this is the only close.
	defer client.Close()
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
	if client, err = takeReadAhead(client, backend); err != nil {
		return
	}
	pipeHalfClose(client, backend)
}

// takeReadAhead sends a ReadAheadConn's unread bytes to backend and returns the
// connection underneath, so that both directions can splice and the client can
// be half-closed; any other connection comes back as it is. Through the
// wrapper, neither was possible: its type is not *net.TCPConn, so every byte
// went through a 32 KiB user-space buffer each way, and it has no CloseWrite,
// so a backend that answered and hung up left the client waiting for more.
func takeReadAhead(client net.Conn, backend io.Writer) (net.Conn, error) {
	ra, ok := client.(ReadAheadConn)
	if !ok {
		return client, nil
	}
	pending, conn := ra.ReadAhead()
	if len(pending) > 0 {
		if _, err := backend.Write(pending); err != nil {
			return conn, err
		}
	}
	return conn, nil
}

// splicedSessions counts the L4 sessions whose bytes splice(2) is moving now.
var splicedSessions atomic.Int64

// SpliceSupported reports whether this build moves L4 session bytes with
// splice(2): Linux does, between two plain TCP sockets.
func SpliceSupported() bool { return spliceSupported }

// SplicedSessions reports how many L4 sessions are being spliced right now:
// both ends plain TCP sockets on a build that splices. A TLS-terminated
// session is copied through a buffer and is not counted.
func SplicedSessions() int64 { return splicedSessions.Load() }

// spliceable reports whether a session between a and b is spliced.
func spliceable(a, b net.Conn) bool {
	_, aTCP := a.(*net.TCPConn)
	_, bTCP := b.(*net.TCPConn)
	return spliceSupported && aTCP && bTCP
}

// pipeHalfClose copies client and backend into each other until both
// directions are done. When one side stops sending, the other is half-closed,
// so it reads EOF while its own direction carries on.
func pipeHalfClose(client, backend net.Conn) {
	if spliceable(client, backend) {
		splicedSessions.Add(1)
		defer splicedSessions.Add(-1)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		copyThenCloseWrite(backend, client)
	}()
	copyThenCloseWrite(client, backend)
	<-done
}

// copyThenCloseWrite copies src to dst -- by splice(2) when both are TCP
// sockets on Linux, through a pooled buffer otherwise -- and then half-closes
// dst.
func copyThenCloseWrite(dst, src net.Conn) {
	if _, err := SpliceCopy(dst, src); err != nil {
		copyPooled(dst, src)
	}
	if c, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = c.CloseWrite()
	}
}

// copyBufSize is io.Copy's own buffer size, so pooling changes allocation,
// not how many bytes move per read.
const copyBufSize = 32 << 10

// copyBufs holds the buffers of sessions splice cannot move -- every session
// of a TLS-terminating entrypoint. io.Copy allocated one per direction per
// session, 64 KiB of garbage for each short session; a session now borrows
// two and returns them when it ends. sync.Pool bounds what it keeps idle by
// releasing it to the collector. It has no New: an empty pool answers nil, and
// copyPooled makes the buffer itself.
var copyBufs sync.Pool

// copyBuf is one direction's copy state: the buffer, and the wrappers that
// make io.CopyBuffer use it. io.CopyBuffer ignores the buffer when dst has
// ReadFrom or src has WriteTo, and a *net.TCPConn has both -- each bringing
// its own 32 KiB allocation when the other end is not a socket it can splice
// to. The wrappers hide both, and live here so that passing them as
// interfaces does not allocate them per copy.
type copyBuf struct {
	buf []byte
	w   writerOnly
	r   readerOnly
}

func newCopyBuf() *copyBuf { return &copyBuf{buf: make([]byte, copyBufSize)} }

// writerOnly and readerOnly hide every method but Write and Read.
type writerOnly struct{ io.Writer }
type readerOnly struct{ io.Reader }

// copyPooled copies src to dst through a buffer from copyBufs.
func copyPooled(dst io.Writer, src io.Reader) {
	cb, _ := copyBufs.Get().(*copyBuf) // nil when the pool is empty
	if cb == nil {
		cb = newCopyBuf()
	}
	cb.w.Writer, cb.r.Reader = dst, src
	_, _ = io.CopyBuffer(&cb.w, &cb.r, cb.buf)
	cb.w.Writer, cb.r.Reader = nil, nil // an idle buffer must not keep a connection alive
	copyBufs.Put(cb)
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
