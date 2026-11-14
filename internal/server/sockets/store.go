// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package sockets

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/gsoultan/gateon/internal/logger"
)

// EnvHandoff turns the handoff off when set to false: listeners are then
// bound afresh at every start, and anything inherited is closed.
const EnvHandoff = "GATEON_SOCKET_HANDOFF"

// MaxStored bounds how many sockets are handed to the service manager. The
// units set FileDescriptorStoreMax to the same number; a gateway with more
// listeners than this keeps the first and binds the rest afresh.
const MaxStored = 64

// The two kinds of socket a gateway listens on.
const (
	networkTCP = "tcp"
	networkUDP = "udp"
)

// inherited is one socket the service manager passed to this process.
type inherited struct {
	// name is the manager's label for it, used to ask for its removal.
	name    string
	file    *os.File
	network string
	addr    netip.AddrPort
}

// Store is the sockets this process inherited and the way to hand new ones
// to the service manager. A nil Store binds plainly and keeps nothing. It is
// safe for concurrent use.
type Store struct {
	mu        sync.Mutex
	inherited []*inherited
	notify    *notifier
	// stored counts the sockets the manager holds for this process.
	stored int
	// kept is the names of the sockets in use, so that dropping an unclaimed
	// one never drops a claimed one that shares its name.
	kept map[string]bool
}

// Listen returns a TCP listener on addr: the inherited one bound there, or a
// new one, which is then handed to the service manager.
func (s *Store) Listen(addr string) (net.Listener, error) {
	if s == nil {
		return net.Listen(networkTCP, addr)
	}
	if in := s.claim(networkTCP, addr); in != nil {
		l, err := net.FileListener(in.file)
		_ = in.file.Close()
		if err == nil {
			logger.L.LogInfo("serving on a socket kept open across the restart", "addr", l.Addr().String())
			return l, nil
		}
		s.drop(in.name)
	}
	l, err := net.Listen(networkTCP, addr)
	if err != nil {
		return nil, err
	}
	if raw, ok := l.(syscall.Conn); ok {
		s.keep(networkTCP, l.Addr(), raw)
	}
	return l, nil
}

// ListenUDP is Listen for a UDP socket.
func (s *Store) ListenUDP(addr string) (*net.UDPConn, error) {
	laddr, err := net.ResolveUDPAddr(networkUDP, addr)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return net.ListenUDP(networkUDP, laddr)
	}
	if in := s.claim(networkUDP, addr); in != nil {
		pc, err := net.FilePacketConn(in.file)
		_ = in.file.Close()
		if conn, ok := pc.(*net.UDPConn); err == nil && ok {
			logger.L.LogInfo("serving on a socket kept open across the restart", "addr", "udp "+conn.LocalAddr().String())
			return conn, nil
		}
		if pc != nil {
			_ = pc.Close()
		}
		s.drop(in.name)
	}
	conn, err := net.ListenUDP(networkUDP, laddr)
	if err != nil {
		return nil, err
	}
	s.keep(networkUDP, conn.LocalAddr(), conn)
	return conn, nil
}

// claim takes the inherited socket of network bound where addr asks, if
// there is one.
func (s *Store) claim(network, addr string) *inherited {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, in := range s.inherited {
		if in.network != network || in.addr.Port() != uint16(port) || !sameHost(host, in.addr.Addr()) {
			continue
		}
		s.inherited = append(s.inherited[:i], s.inherited[i+1:]...)
		s.kept[in.name] = true
		return in
	}
	return nil
}

// sameHost reports whether a socket bound to bound is what listening on
// host would bind. No host means every address, which either family's
// wildcard is; a named address must be the one bound. "0.0.0.0" is not "::":
// the second also takes IPv6.
func sameHost(host string, bound netip.Addr) bool {
	if host == "" {
		return bound.IsUnspecified()
	}
	want, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return want.Unmap().WithZone("") == bound.Unmap().WithZone("")
}

// keep hands a newly bound socket to the service manager.
func (s *Store) keep(network string, addr net.Addr, raw syscall.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.notify == nil {
		return
	}
	if s.stored >= MaxStored {
		logger.L.LogWarn("more listeners than the service manager is asked to keep; this one is bound afresh at each restart",
			"addr", addr.String(), "kept", MaxStored)
		return
	}
	name := storeName(network, addr)
	if err := s.notify.store(name, raw); err != nil {
		logger.L.LogWarn("could not hand a listening socket to the service manager; it is bound afresh at the next restart",
			"addr", addr.String(), "error", err)
		return
	}
	s.stored++
	s.kept[name] = true
}

// storeName labels a socket for the service manager, which allows printable
// ASCII without a colon.
func storeName(network string, addr net.Addr) string {
	return network + "-" + strings.ReplaceAll(addr.String(), ":", "_")
}

// drop asks the manager to forget the sockets called name.
func (s *Store) drop(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropLocked(name)
}

func (s *Store) dropLocked(name string) {
	delete(s.kept, name)
	if s.stored > 0 {
		s.stored--
	}
	if s.notify == nil || name == "" {
		return
	}
	if err := s.notify.remove(name); err != nil {
		logger.L.LogWarn("could not ask the service manager to drop a socket", "name", name, "error", err)
	}
}

// DiscardUnclaimed closes every inherited socket no listener asked for and
// has the manager drop it. It is called once the entrypoints have started:
// what is left then belongs to an entrypoint that was removed or moved, and
// a socket nobody accepts from would take connections and never answer.
func (s *Store) DiscardUnclaimed() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, in := range s.inherited {
		_ = in.file.Close()
		logger.L.LogInfo("closing a socket kept across the restart that no entrypoint listens on any more",
			"addr", in.network+" "+in.addr.String())
		if s.kept[in.name] {
			// A socket in use carries the same name; the manager removes by
			// name, so this one is closed here and left to it.
			continue
		}
		s.dropLocked(in.name)
	}
	s.inherited = nil
}
