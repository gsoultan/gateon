// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package wsinspect holds back what a client sends on an upgraded WebSocket
// connection until each message has been judged.
//
// A WebSocket upgrade is one HTTP request followed by a connection the gateway
// relays byte for byte. Every check in the middleware chain runs on that one
// request; the messages that follow, which carry the same SQL, the same
// template expressions and the same paths as a request body would, were
// forwarded unread. This package reads the client's side of the connection as
// frames (RFC 6455), reassembles each message up to a bound, and releases its
// bytes to the backend only after the caller's Inspector has allowed it.
//
// It knows nothing about the WAF. What an attack is belongs to the Inspector;
// what a frame is belongs here, because whoever owns the connection owns its
// framing.
//
// Only the client's direction is read. What the backend sends is relayed
// untouched.
package wsinspect

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Verdict is what an Inspector decides about one message.
type Verdict uint8

const (
	// Allow releases the message to the backend.
	Allow Verdict = iota
	// Refuse closes the connection; the message never reaches the backend.
	Refuse
)

// Inspector judges one complete, unmasked client message. payload is valid
// only until Inspector returns. text reports the opcode the client chose, as a
// hint: both kinds are judged, because an opcode is the client's to write.
type Inspector func(payload []byte, text bool) Verdict

// Reason says why a connection was closed, for the caller's counters.
type Reason string

const (
	// ReasonRefused: the Inspector refused a message.
	ReasonRefused Reason = "refused"
	// ReasonOversize: a message was larger than Options.MaxMessage.
	ReasonOversize Reason = "oversize"
	// ReasonProtocol: the client's bytes were not valid WebSocket frames, or
	// used an extension the gateway did not let it negotiate.
	ReasonProtocol Reason = "protocol"
)

// Options configures one inspected connection.
type Options struct {
	// MaxMessage is the largest message, in payload bytes, that is held for
	// inspection. It bounds what this connection holds: a message in one
	// frame is held once, and one in several frames at most 2.25 times
	// (its wire bytes, a quarter more for their headers, and its payload).
	MaxMessage int
	// ForwardOversize forwards a message past MaxMessage unread instead of
	// closing the connection. It is for a route that records and does not
	// refuse; on any other route it is the bypass padding a message buys.
	ForwardOversize bool
	// Inspect judges each message. Required.
	Inspect Inspector
	// OnClose is called once when this package closes the connection, and
	// once per forwarded oversize message. Optional.
	OnClose func(Reason)
}

// DefaultMaxMessage is used when Options.MaxMessage is not positive.
const DefaultMaxMessage = 64 << 10

// retainCap is the largest buffer an idle connection keeps between messages.
// A connection that carried one large message must not hold its size for the
// hours it then stays open.
const retainCap = 4 << 10

// closeWriteTimeout bounds the close frame written to a client being refused.
// A client that will not read does not get to hold the connection open.
const closeWriteTimeout = time.Second

// WebSocket close codes (RFC 6455 section 7.4.1).
const (
	closeProtocolError   = 1002
	closePolicyViolation = 1008
	closeMessageTooBig   = 1009
)

// ErrClosed is returned from Read after this package has closed the
// connection.
var ErrClosed = errors.New("wsinspect: connection closed by inspection")

// ExtensionsHeader is the request header an inspected upgrade must not carry.
//
// permessage-deflate compresses each message, with a dictionary carried from
// one message to the next. A compressed message cannot be judged, and whoever
// owns the connection decides what is negotiated on it, so the offer is
// removed and the backend has nothing to accept. A frame that claims an
// extension anyway is a protocol error.
const ExtensionsHeader = "Sec-Websocket-Extensions"

// Guard returns w with its Hijack replaced: the connection a handler takes
// from it has its client side inspected under opts. Everything else about w is
// unchanged, so a backend that answers the upgrade with an ordinary response
// still goes through the chain.
//
// Every hijack is guarded, not only one whose request names WebSocket. The
// Upgrade header is the client's to write; a route that inspects WebSocket
// messages carries WebSocket, and anything else on it fails to parse and is
// closed.
func Guard(w http.ResponseWriter, opts Options) http.ResponseWriter {
	return &guardedWriter{ResponseWriter: w, opts: opts}
}

type guardedWriter struct {
	http.ResponseWriter
	opts Options
}

// Unwrap lets http.ResponseController reach the writer underneath.
func (g *guardedWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

// Flush forwards to the writer underneath, for a backend that declined the
// upgrade and streams an ordinary response instead.
func (g *guardedWriter) Flush() {
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack takes the connection and returns it with its client side inspected.
func (g *guardedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := g.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return conn, rw, err
	}
	// Whatever net/http had already read from the client belongs to the
	// first frame. It is moved behind the inspection; left in rw.Reader it
	// would reach the backend around it.
	var early []byte
	if n := rw.Reader.Buffered(); n > 0 {
		head, _ := rw.Peek(n)
		early = bytes.Clone(head)
	}
	inspected := NewConn(conn, early, g.opts)
	return inspected, bufio.NewReadWriter(bufio.NewReaderSize(inspected, 16), rw.Writer), nil
}

// Conn is a client connection whose Read returns only bytes of messages the
// Inspector allowed. Read is for one goroutine; Write and Close may be called
// from another.
type Conn struct {
	net.Conn
	src  *bufio.Reader
	opts Options

	// out holds bytes cleared for the backend; outOff is how far Read has got.
	out    []byte
	outOff int
	// raw holds the wire bytes of the message being assembled, and msg its
	// unmasked payload when it arrives in more than one frame.
	raw       []byte
	msg       []byte
	assembled int
	inMessage bool
	text      bool
	// pass counts payload bytes to relay unread, and passing says the rest of
	// the current message goes the same way (ForwardOversize).
	pass    int64
	passing bool

	writeMu sync.Mutex
	closed  bool
}

// NewConn wraps conn. early is what was already read from the client before
// the caller took the connection, and is consumed first.
func NewConn(conn net.Conn, early []byte, opts Options) *Conn {
	if opts.MaxMessage <= 0 {
		opts.MaxMessage = DefaultMaxMessage
	}
	var r io.Reader = conn
	if len(early) > 0 {
		r = io.MultiReader(bytes.NewReader(early), conn)
	}
	return &Conn{Conn: conn, src: bufio.NewReaderSize(r, 4<<10), opts: opts}
}

// Read returns bytes of client frames that have been cleared for the backend.
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if c.closed {
			return 0, ErrClosed
		}
		if c.outOff < len(c.out) {
			n := copy(p, c.out[c.outOff:])
			c.outOff += n
			c.releaseDrained()
			return n, nil
		}
		if c.pass > 0 {
			return c.readPassing(p)
		}
		if err := c.readFrame(); err != nil {
			return 0, err
		}
	}
}

// Write relays the backend's bytes to the client. The lock orders them
// against the one close frame this package may write.
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.Conn.Write(p)
}

// CloseWrite half-closes the connection towards the client, the way the proxy
// does for a connection it holds directly: the TCP half-close, under TLS too.
func (c *Conn) CloseWrite() error {
	under := c.Conn
	if tc, ok := under.(*tls.Conn); ok {
		under = tc.NetConn()
	}
	if cw, ok := under.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *Conn) releaseDrained() {
	if c.outOff < len(c.out) {
		return
	}
	c.outOff = 0
	if cap(c.out) > retainCap {
		c.out = nil
		return
	}
	c.out = c.out[:0]
}

func (c *Conn) readPassing(p []byte) (int, error) {
	if int64(len(p)) > c.pass {
		p = p[:c.pass]
	}
	n, err := c.src.Read(p)
	c.pass -= int64(n)
	if n > 0 {
		return n, nil
	}
	return 0, err
}

// refuse tells the client why, closes the connection and reports it.
func (c *Conn) refuse(code uint16, why Reason) error {
	c.closed = true
	c.raw, c.msg, c.out = nil, nil, nil
	frame := [4]byte{0x88, 2}
	binary.BigEndian.PutUint16(frame[2:], code)

	c.writeMu.Lock()
	_ = c.SetWriteDeadline(time.Now().Add(closeWriteTimeout))
	_, _ = c.Conn.Write(frame[:])
	c.writeMu.Unlock()
	_ = c.Close()

	if c.opts.OnClose != nil {
		c.opts.OnClose(why)
	}
	return ErrClosed
}
