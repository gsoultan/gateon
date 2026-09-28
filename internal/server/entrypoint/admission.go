// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
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
	slots *connSlots
}

func (l *cappedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.slots.take() {
			return &slotConn{Conn: c, slots: l.slots}, nil
		}
		_ = c.Close()
		l.slots.refused()
	}
}

// slotConn is an admitted connection. Closing it frees its slot -- once,
// however often it is closed: net/http closes a connection more than once, and
// a TLS connection closes the one beneath it too.
type slotConn struct {
	net.Conn
	slots  *connSlots
	closed atomic.Bool
}

func (c *slotConn) Close() error {
	err := c.Conn.Close()
	if c.closed.CompareAndSwap(false, true) {
		c.slots.release()
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
// cannot turn away for us.
type cappedQUICListener struct {
	http3.QUICListener
	slots *connSlots
}

func (l *cappedQUICListener) Accept(ctx context.Context) (*quic.Conn, error) {
	for {
		c, err := l.QUICListener.Accept(ctx)
		if err != nil {
			return nil, err
		}
		if l.slots.take() {
			// The slot is the connection's, not the accept call's: it is
			// freed when the connection's own context ends, as it closes.
			//nolint:contextcheck // bound to the connection's lifetime on purpose, not to ctx.
			context.AfterFunc(c.Context(), l.slots.release)
			return c, nil
		}
		_ = c.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad), "")
		l.slots.refused()
	}
}

// peerIP is the address c comes from, without its port -- the form the IP
// mitigation list keeps addresses in. An IPv4 client of a dual-stack listener
// is written as IPv4.
func peerIP(c net.Conn) string {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP.String()
	}
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
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
		Details:     "Connection refused at TCP entrypoint " + s.ep.Id + ": the address is on the IP mitigation list",
	})
	return true
}
