// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package mgmtaddr knows where this gateway's management listener answers, so
// that nothing in the data plane connects to it (ADR 0052).
//
// A service whose target was 127.0.0.1:<management port>, behind a Host()
// route on a public entrypoint, served the dashboard, sign-in and API to the
// internet from loopback: the management listener saw the gateway's own
// connection, which its bind, its allowlist (ADR 0040), its per-address cap
// and the sign-in lockout all trust. The gateway therefore never proxies to
// its own management listener -- a target is refused when it is saved
// (CheckTarget) and the connection is refused when it is dialled (Control),
// because a name can resolve somewhere else tomorrow.
//
// "Reaches the management listener" is the management port on any address of
// this host: loopback, the unspecified address (a connect to which lands on
// this host), and every address of its interfaces. That is wider than the
// listener's own bind on purpose. It is what a wildcard bind answers on, it is
// one comparison wherever the listener is bound, and a backend on this host
// that shares the management port's number on another of its addresses is
// rare enough to be told to move.
package mgmtaddr

import (
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// port is the management listener's TCP port, 0 while none has bound.
var port atomic.Uint32

// Register records the port the management listener bound and returns the
// one it replaces (0 for none), so a test can put it back.
func Register(p int) int {
	if p < 0 || p > 65535 {
		p = 0
	}
	return int(port.Swap(uint32(p)))
}

// RegisterListener records a's port when a is a TCP address, and returns the
// function that forgets it again once the listener has closed -- unless
// another listener has registered since -- so a port the system hands to
// something else later is not refused for having been the management port.
func RegisterListener(a net.Addr) (unregister func()) {
	t, ok := a.(*net.TCPAddr)
	if !ok || t.Port <= 0 || t.Port > 65535 {
		return func() {}
	}
	p := uint32(t.Port)
	port.Store(p)
	return func() { port.CompareAndSwap(p, 0) }
}

// Port is the management listener's port, or 0 when none has bound.
func Port() int { return int(port.Load()) }

// Reaches reports whether a TCP connection to ap would reach the management
// listener: its port, on an address of this host. It does not allocate; the
// port is compared first, so a connection to any other port costs one load
// and one comparison.
func Reaches(ap netip.AddrPort) bool {
	p := port.Load()
	if p == 0 || uint32(ap.Port()) != p {
		return false
	}
	return isLocal(ap.Addr())
}

// isLocal reports whether a is an address of this host.
func isLocal(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	if a.IsLoopback() || a.IsUnspecified() {
		return true
	}
	return currentHostAddrs().has(a)
}

// hostAddrsTTL is how long a reading of the interfaces' addresses is used. It
// is read only for a connection to the management port's number, so the cost
// of a fresh reading is paid rarely; the TTL only bounds how stale it can be
// after an address is added.
const hostAddrsTTL = 30 * time.Second

// hostAddrs is one reading of this host's interface addresses.
type hostAddrs struct {
	at    time.Time
	addrs []netip.Addr // bounded by the host's interface addresses
}

func (h *hostAddrs) has(a netip.Addr) bool {
	for _, x := range h.addrs {
		if x == a {
			return true
		}
	}
	return false
}

var hostCache atomic.Pointer[hostAddrs]

// currentHostAddrs is the latest reading, refreshed when older than the TTL.
// Two goroutines refreshing at once both store a correct reading; neither
// waits for the other.
func currentHostAddrs() *hostAddrs {
	now := time.Now()
	if h := hostCache.Load(); h != nil && now.Sub(h.at) < hostAddrsTTL {
		return h
	}
	h := &hostAddrs{at: now, addrs: readHostAddrs()}
	hostCache.Store(h)
	return h
}

// readHostAddrs lists the addresses of this host's interfaces. An error reads
// as none: loopback and the unspecified address are still recognised, and the
// save-time check names the target before it is ever dialled.
func readHostAddrs() []netip.Addr {
	ifAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	out := make([]netip.Addr, 0, len(ifAddrs))
	for _, a := range ifAddrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(n.IP); ok {
			out = append(out, ip.Unmap().WithZone(""))
		}
	}
	return out
}
