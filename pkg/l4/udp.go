// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// UDPSessionProxy proxies UDP with session-based client-backend correlation.
// Each client gets a dedicated connected UDP socket to the backend, ensuring
// correct response routing. Sessions expire after idle timeout.
// DefaultUDPMaxSessions bounds the session table when none is configured.
//
// Every entry costs a map slot, a connected UDP socket (a file descriptor), a
// goroutine and that goroutine's 64KiB read buffer, so the table is sized by
// what the host can afford rather than by what a client might ask for: 4096
// sessions is roughly 256MiB of read buffers plus 4096 descriptors, which fits
// the 2 core / 2GB reference deployment with room to spare.
const DefaultUDPMaxSessions = 4096

type UDPSessionProxy struct {
	backendAddrs []string
	policy       string
	timeout      time.Duration
	maxSessions  int
	sessions     map[string]*udpSession
	mu           sync.Mutex
	next         uint64
	stop         chan struct{}

	// dropped counts packets refused because the table was full, so an
	// operator can tell a saturated proxy apart from a silent one.
	dropped atomic.Uint64
}

type udpSession struct {
	clientAddr *net.UDPAddr
	conn       *net.UDPConn
	lastUsed   time.Time
}

// NewUDPSessionProxy creates a session-based UDP proxy. maxSessions bounds the
// session table; 0 selects DefaultUDPMaxSessions.
func NewUDPSessionProxy(backendAddrs []string, policy string, sessionTimeoutSec, maxSessions int) *UDPSessionProxy {
	if len(backendAddrs) == 0 {
		return nil
	}
	timeout := 60 * time.Second
	if sessionTimeoutSec > 0 {
		timeout = time.Duration(sessionTimeoutSec) * time.Second
	}
	if policy == "" {
		policy = "round_robin"
	}
	if maxSessions <= 0 {
		maxSessions = DefaultUDPMaxSessions
	}
	p := &UDPSessionProxy{
		backendAddrs: backendAddrs,
		policy:       policy,
		timeout:      timeout,
		maxSessions:  maxSessions,
		sessions:     make(map[string]*udpSession),
		stop:         make(chan struct{}),
	}
	go p.cleanupLoop()
	return p
}

func (p *UDPSessionProxy) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			p.expireSessions()
		}
	}
}

func (p *UDPSessionProxy) expireSessions() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(time.Now())
}

// expireLocked drops idle sessions. The caller must hold p.mu; HandlePacket
// calls it inline when the table is full, which is the case idle expiry on a
// 10-second ticker cannot cover on its own.
func (p *UDPSessionProxy) expireLocked(now time.Time) {
	for key, s := range p.sessions {
		if now.Sub(s.lastUsed) > p.timeout {
			_ = s.conn.Close()
			delete(p.sessions, key)
		}
	}
}

// Sessions reports the number of live sessions.
func (p *UDPSessionProxy) Sessions() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sessions)
}

// DroppedPackets reports packets refused because the session table was full.
func (p *UDPSessionProxy) DroppedPackets() uint64 { return p.dropped.Load() }

func (p *UDPSessionProxy) pickBackend() string {
	if len(p.backendAddrs) == 0 {
		return ""
	}
	idx := p.next % uint64(len(p.backendAddrs))
	p.next++
	return p.backendAddrs[idx]
}

// HandlePacket handles an incoming UDP packet from a client.
// The data slice must not be modified after the call; the caller may reuse the buffer.
func (p *UDPSessionProxy) HandlePacket(serverConn *net.UDPConn, clientAddr *net.UDPAddr, data []byte) {
	key := clientAddr.String()
	p.mu.Lock()
	s, ok := p.sessions[key]
	if !ok {
		// Admission control. The key is the client's source address, and for
		// UDP that is simply what the sender wrote in the packet — unverified
		// and free to vary per datagram. Without a ceiling, one host emitting
		// spoofed sources makes the gateway allocate a socket, a goroutine and
		// a 64KiB buffer per address until it runs out of descriptors or
		// memory, whichever comes first. Idle expiry alone does not bound it:
		// at any rate above maxSessions/timeout, arrivals outrun the sweep.
		//
		// Reclaim idle sessions first, then refuse. Refusing costs a new client
		// its packets while the table is full; the alternative, evicting to make
		// room, would let whoever sends the most addresses displace established
		// sessions, which hands the attacker the outcome instead of denying it.
		if len(p.sessions) >= p.maxSessions {
			p.expireLocked(time.Now())
			if len(p.sessions) >= p.maxSessions {
				p.mu.Unlock()
				p.dropped.Add(1)
				return
			}
		}

		backendAddr := p.pickBackend()
		if backendAddr == "" {
			p.mu.Unlock()
			return
		}
		raddr, err := net.ResolveUDPAddr("udp", backendAddr)
		if err != nil {
			p.mu.Unlock()
			return
		}
		conn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			p.mu.Unlock()
			return
		}
		s = &udpSession{clientAddr: clientAddr, conn: conn, lastUsed: time.Now()}
		p.sessions[key] = s
		p.mu.Unlock()

		go func() {
			buf := make([]byte, 65535)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					p.mu.Lock()
					delete(p.sessions, key)
					p.mu.Unlock()
					_ = conn.Close()
					return
				}
				p.mu.Lock()
				s.lastUsed = time.Now()
				client := s.clientAddr
				p.mu.Unlock()
				_, _ = serverConn.WriteToUDP(buf[:n], client)
			}
		}()
	} else {
		s.lastUsed = time.Now()
		p.mu.Unlock()
	}
	_, _ = s.conn.Write(data)
}

// Stop closes all sessions. Call when shutting down.
func (p *UDPSessionProxy) Stop() {
	close(p.stop)
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.sessions {
		_ = s.conn.Close()
	}
	p.sessions = make(map[string]*udpSession)
}
