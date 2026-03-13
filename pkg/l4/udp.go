package l4

import (
	"net"
	"sync"
	"time"
)

// UDPSessionProxy proxies UDP with session-based client-backend correlation.
// Each client gets a dedicated connected UDP socket to the backend, ensuring
// correct response routing. Sessions expire after idle timeout.
type UDPSessionProxy struct {
	backendAddrs []string
	policy       string
	timeout      time.Duration
	sessions     map[string]*udpSession
	mu           sync.Mutex
	next         uint64
	stop         chan struct{}
}

type udpSession struct {
	clientAddr *net.UDPAddr
	conn       *net.UDPConn
	lastUsed   time.Time
}

// NewUDPSessionProxy creates a session-based UDP proxy.
func NewUDPSessionProxy(backendAddrs []string, policy string, sessionTimeoutSec int) *UDPSessionProxy {
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
	p := &UDPSessionProxy{
		backendAddrs: backendAddrs,
		policy:       policy,
		timeout:      timeout,
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
	now := time.Now()
	for key, s := range p.sessions {
		if now.Sub(s.lastUsed) > p.timeout {
			_ = s.conn.Close()
			delete(p.sessions, key)
		}
	}
}

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
