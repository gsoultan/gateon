// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// What an entrypoint admits is decided when a connection is accepted: no more
// than its max_connections at once, on every kind of entrypoint, and on a TCP
// entrypoint nothing from an address on the IP mitigation list (ADR 0032).

// connLimit is the most connections ep holds open at once: its
// max_connections, or the resource profile's default when that is 0. It was
// stored and shown and read by nothing, so no entrypoint had a cap at all.
func connLimit(ep *gateonv1.EntryPoint) int {
	if n := int(ep.GetMaxConnections()); n > 0 {
		return n
	}
	return config.CurrentTierDefaults().EntryPointMaxConnections
}

// perAddrConnLimit is the most concurrent connections one source address may
// hold on an entrypoint: GATEON_ENTRYPOINT_MAX_CONN_PER_ADDR when it is set,
// else the resource profile's default (config.TierDefaults). 0, or a negative
// value, disables the per-address cap. It complements connLimit, which bounds
// the entrypoint as a whole -- both apply, and this is the tighter for a single
// client: connLimit stops a flood costing the gateway without bound, this stops
// one client being that flood (ADR 0036).
func perAddrConnLimit() int {
	if v, ok := os.LookupEnv("GATEON_ENTRYPOINT_MAX_CONN_PER_ADDR"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return config.CurrentTierDefaults().EntryPointMaxConnPerAddr
}

// maxHeaderBytesEnv overrides the tier's request-header cap, in bytes.
const maxHeaderBytesEnv = "GATEON_MAX_HEADER_BYTES"

// maxHeaderBytes is the most request-header bytes any HTTP listener buffers
// for one request -- the entrypoints over HTTP/1, HTTP/2 and HTTP/3, and the
// management listener: GATEON_MAX_HEADER_BYTES when it is a positive integer,
// else the resource profile's default (config.TierDefaults). A request past it
// is refused with 431 (ADR 0042). It was 1 MiB, and a connection still sending
// its header holds what it has sent, so 1000 such connections -- the minimal
// tier's cap -- took the 2 GB host's process from 508 MiB to 1265 MiB.
func maxHeaderBytes() int {
	if v := strings.TrimSpace(os.Getenv(maxHeaderBytesEnv)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
		logger.L.LogWarn("ignoring an invalid header cap; using the profile default",
			"env", maxHeaderBytesEnv, "value", v)
	}
	return config.CurrentTierDefaults().MaxHeaderBytes
}

// tcpPerAddrReason and httpPerAddrReason are the fixed labels a per-address
// refusal is counted under. Neither is "max_connections_per_ip" -- the
// request-inflight counter -- so both fall in with the other connection-limit
// rejections, as ADR 0036 says they should.
const (
	tcpPerAddrReason  = "tcp_max_conn_per_addr"
	httpPerAddrReason = "http_max_conn_per_addr"
)

// perAddrLimiter caps concurrent connections per source address on one
// entrypoint. The map holds an entry only while an address has a connection
// open, so it is bounded by the entrypoint's own connection cap, not by the
// address space: many addresses at once are already bounded by connLimit, and
// an entry is deleted when its last connection closes. Loopback and the
// mitigation allowlist are exempt and never tracked, so a local proxy -- behind
// which every client is loopback -- is not capped by the one address it shares.
type perAddrLimiter struct {
	mu     sync.Mutex
	counts map[string]int
	limit  int
	warn   limitWarning
}

// newPerAddrLimiter builds a limiter, or nil when limit is not positive, which
// is the cap disabled: a nil *perAddrLimiter admits every connection.
func newPerAddrLimiter(limit int) *perAddrLimiter {
	if limit <= 0 {
		return nil
	}
	return &perAddrLimiter{counts: make(map[string]int), limit: limit}
}

// acquire reserves a slot for ip and reports whether one was free. A nil
// limiter (the cap disabled) and an exempt address always succeed and hold no
// entry, so the map never grows for loopback or the allowlist.
func (p *perAddrLimiter) acquire(ip string) bool {
	if p == nil || perAddrExempt(ip) {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.counts[ip] >= p.limit {
		return false
	}
	p.counts[ip]++
	return true
}

// release returns ip's slot; its entry is deleted when the last connection
// from it closes, so the map retains no address that holds nothing.
func (p *perAddrLimiter) release(ip string) {
	if p == nil || perAddrExempt(ip) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch n := p.counts[ip]; {
	case n <= 1:
		delete(p.counts, ip)
	default:
		p.counts[ip] = n - 1
	}
}

// perAddrExempt reports whether ip is never capped per address: an address that
// did not resolve, loopback, and GATEON_MITIGATION_ALLOWLIST -- the same
// exemption the IP block applies (identity.ExemptFromEnforcement), so the two
// agree on which addresses are never turned away.
func perAddrExempt(ip string) bool {
	return ip == "" || identity.ExemptFromEnforcement(ip)
}

// atLimitWarningEvery spaces the warnings a full entrypoint logs: every
// refusal counts, but a flood of them must not become a flood of log lines.
const atLimitWarningEvery = time.Minute

// limitWarning is when a full entrypoint last said so, in unix nanoseconds.
type limitWarning struct{ last atomic.Int64 }

// due reports whether a refusal at now should log, at most once per
// atLimitWarningEvery.
func (w *limitWarning) due(now time.Time) bool {
	last := w.last.Load()
	if now.UnixNano()-last < int64(atLimitWarningEvery) {
		return false
	}
	return w.last.CompareAndSwap(last, now.UnixNano())
}

// httpConnLimitReason is the fixed label an HTTP entrypoint's refusals are
// counted under, with the other connection-limit rejections.
const httpConnLimitReason = "http_max_connections"

// connSlots is an HTTP entrypoint's connection limit and the connections
// holding it. A connection is what holds a slot, never a request: an HTTP/1
// connection for as long as it is open, idle between keep-alive requests
// included -- an idle connection keeps its descriptor, goroutine and buffers
// -- and an HTTP/2 one however many streams it carries, which
// h2MaxConcurrentStreams bounds. An HTTP/3 entrypoint's QUIC connections take
// their slots from the same limit.
type connSlots struct {
	epID  string
	limit int64
	held  atomic.Int64
	warn  limitWarning
}

func newConnSlots(ep *gateonv1.EntryPoint) *connSlots {
	return &connSlots{epID: ep.Id, limit: int64(connLimit(ep))}
}

// unlimitedSlots is a connSlots no connection count reaches: for a listener
// that has a per-address cap and, on purpose, no listener-wide one.
func unlimitedSlots(id string) *connSlots {
	return &connSlots{epID: id, limit: math.MaxInt64}
}

// take claims a slot, and reports false when every one is held.
func (s *connSlots) take() bool {
	for {
		n := s.held.Load()
		if n >= s.limit {
			return false
		}
		if s.held.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

func (s *connSlots) release() { s.held.Add(-1) }

// refused counts a connection that was closed as soon as it was accepted,
// because every slot was held, and says so at most once a minute.
func (s *connSlots) refused() {
	telemetry.IncInflightRejected(httpConnLimitReason)
	if s.warn.due(time.Now()) {
		logger.L.LogWarn("HTTP entrypoint at its connection limit, refusing new connections",
			"ep", s.epID, "max_connections", s.limit)
	}
}

// cappedListener is an HTTP entrypoint's listener. A connection accepted while
// every slot is held is closed at once and the loop goes back to accepting: it
// never waits for a slot, so each connection past the limit is answered as it
// arrives instead of queueing in the kernel behind the ones that are.
type cappedListener struct {
	net.Listener
	slots   *connSlots
	perAddr *perAddrLimiter
}

func (l *cappedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if !l.slots.take() {
			// Counted before the close, so a client that sees the close
			// can already read the count: the other order let a reader
			// look between the two and find the refusal uncounted.
			l.slots.refused()
			_ = c.Close()
			continue
		}
		// The per-address cap is the tighter of the two, so it is checked
		// after the entrypoint-wide slot is held and gives it back on refusal.
		// peerIP is read only when the cap is on, so an entrypoint without one
		// pays nothing for it.
		ip := ""
		if l.perAddr != nil {
			ip = peerIP(c)
			if !l.perAddr.acquire(ip) {
				l.slots.release()
				l.refusedPerAddr()
				_ = c.Close()
				continue
			}
		}
		return &slotConn{Conn: c, slots: l.slots, perAddr: l.perAddr, addr: ip}, nil
	}
}

// refusedPerAddr counts a connection closed at accept because its source
// address already holds its per-address limit, and says so at most once a
// minute -- counted with the other connection-limit rejections.
func (l *cappedListener) refusedPerAddr() {
	telemetry.IncInflightRejected(httpPerAddrReason)
	if l.perAddr.warn.due(time.Now()) {
		logger.L.LogWarn("HTTP entrypoint refusing a connection: source address at its per-address connection limit",
			"ep", l.slots.epID, "max_conn_per_addr", l.perAddr.limit)
	}
}

// slotConn is an admitted connection. Closing it frees its slot -- once,
// however often it is closed: net/http closes a connection more than once, and
// a TLS connection closes the one beneath it too.
type slotConn struct {
	net.Conn
	slots   *connSlots
	perAddr *perAddrLimiter
	addr    string
	closed  atomic.Bool
}

func (c *slotConn) Close() error {
	err := c.Conn.Close()
	if c.closed.CompareAndSwap(false, true) {
		c.slots.release()
		c.perAddr.release(c.addr)
	}
	return err
}

// CloseWrite half-closes the connection, as the *net.TCPConn beneath it does:
// net/http sends its FIN that way before it closes a connection it answered
// early, and the WebSocket proxy hands its client EOF that way when the
// backend is done. A wrapper without it would silently lose both.
func (c *slotConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

// ReadFrom keeps the socket's own ReadFrom, which is sendfile(2) or splice(2),
// within net/http's reach: it sends a response body from a file that way.
func (c *slotConn) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := c.Conn.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(writerOnly{c.Conn}, r)
}

// writerOnly hides every method of a writer but Write, so io.Copy cannot hand
// the copy back to the ReadFrom that called it.
type writerOnly struct{ io.Writer }

// cappedQUICListener is cappedListener for the QUIC connections of an HTTP/3
// entrypoint, which take their slots from the same limit as its TCP ones: a
// client uses one or the other, and each costs the gateway a connection's
// state and goroutines. A QUIC connection is what holds a slot, until it
// closes, whatever number of streams it carries. Its handshake is done by the
// time it is accepted, so refusing one costs more than refusing a TCP
// connection does -- a cost of QUIC living in user space, which the kernel
// cannot turn away for us. CloseWithError returns once the connection's own
// loop has sent the close, which it does at once: the accept loop waits for
// that, never for a slot, and a goroutine per refusal would only move the
// wait somewhere nothing joins it.
type cappedQUICListener struct {
	http3.QUICListener
	slots   *connSlots
	perAddr *perAddrLimiter
}

func (l *cappedQUICListener) Accept(ctx context.Context) (*quic.Conn, error) {
	for {
		c, err := l.QUICListener.Accept(ctx)
		if err != nil {
			return nil, err
		}
		if !l.slots.take() {
			l.slots.refused()
			_ = c.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad), "")
			continue
		}
		ip := ""
		if l.perAddr != nil {
			ip = addrIP(c.RemoteAddr())
			if !l.perAddr.acquire(ip) {
				l.slots.release()
				l.refusedPerAddr()
				_ = c.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad), "")
				continue
			}
		}
		// The slots are the connection's, not the accept call's: freed when
		// the connection's own context ends, as it closes.
		//nolint:contextcheck // bound to the connection's lifetime on purpose, not to ctx.
		context.AfterFunc(c.Context(), func() {
			l.slots.release()
			l.perAddr.release(ip)
		})
		return c, nil
	}
}

// refusedPerAddr counts a QUIC connection closed at accept because its source
// address already holds its per-address limit, and says so at most once a
// minute -- counted with the other connection-limit rejections.
func (l *cappedQUICListener) refusedPerAddr() {
	telemetry.IncInflightRejected(httpPerAddrReason)
	if l.perAddr.warn.due(time.Now()) {
		logger.L.LogWarn("HTTP/3 entrypoint refusing a connection: source address at its per-address connection limit",
			"ep", l.slots.epID, "max_conn_per_addr", l.perAddr.limit)
	}
}

// peerIP is the address c comes from, without its port -- the form the IP
// mitigation list keeps addresses in. An IPv4 client of a dual-stack listener
// is written as IPv4.
func peerIP(c net.Conn) string {
	return addrIP(c.RemoteAddr())
}

// addrIP is the host part of a, without its port. It handles the TCP and UDP
// address types without an allocation for the string form, and falls back to
// SplitHostPort for anything else -- the QUIC connections of an HTTP/3
// entrypoint arrive as *net.UDPAddr.
func addrIP(a net.Addr) string {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.IP.String()
	case *net.UDPAddr:
		return v.IP.String()
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return ""
	}
	return host
}

// refuseBlocked closes c, and reports true, when its client is on the IP
// mitigation list and not exempt from it -- the rule, and the only rule, the
// HTTP entrypoints apply (identity.AddressBlocked). It runs on the
// connection's own goroutine, never the accept loop: the list is read from
// the database when its cache has no answer for the address, and one slow
// lookup must not hold up every connection behind it.
//
// Each refusal is recorded as the HTTP path records one, as an ip_mitigation
// threat: it is counted on gateon_middleware_advanced_security_blocked_total
// and listed in the Security Hub, where the operator who blocked the address
// can see the block working. The record is dropped, never waited for, when the
// store is behind.
func (s *tcpServer) refuseBlocked(c net.Conn) bool {
	ip := peerIP(c)
	if !s.blocked(ip) {
		return false
	}
	_ = c.Close()
	telemetry.RecordSecurityThreat(telemetry.SecurityThreat{
		Type:        "ip_mitigation",
		SourceIP:    ip,
		Category:    "threat_intel",
		Severity:    kind.SeverityHigh,
		ActionTaken: kind.ActionBlocked,
		Details: "Connection refused at TCP entrypoint " + s.ep.Id +
			": the address is on the IP mitigation list or listed by an IP reputation feed",
	})
	return true
}
