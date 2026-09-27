// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"context"
	"errors"
	"net"
	"time"
)

// SpeculativeProxy is a TCPProxy that can connect to a backend before it is
// sure the connection will be used. The TCP entrypoint opens one for a client
// that has said nothing, and waits to see who speaks first: a backend that
// greets is a server-first protocol and gets the session; a client that
// speaks is routed by what it said, and the backend connection is closed
// unused.
type SpeculativeProxy interface {
	TCPProxy
	DialBackend(ctx context.Context, client net.Conn) (Backend, error)
}

var _ SpeculativeProxy = (*TCPBackendPool)(nil)

// errNoBackend is DialBackend's answer when every backend is down.
var errNoBackend = errors.New("l4: no backend available")

// Backend is a connection a pool opened to one of its backends for one
// client, and the pool slot it holds. Exactly one of Close and Proxy must be
// called on it, once: both free the slot.
type Backend struct {
	conn net.Conn
	pool *TCPBackendPool
	addr string
}

// dialTimeout bounds a backend connect.
const dialTimeout = 10 * time.Second

// DialBackend picks a backend for client and connects to it, sending the
// PROXY header first when the pool sends one.
func (p *TCPBackendPool) DialBackend(ctx context.Context, client net.Conn) (Backend, error) {
	addr := p.Pick()
	if addr == "" {
		return Backend{}, errNoBackend
	}
	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		p.Release(addr)
		return Backend{}, err
	}
	b := Backend{conn: conn, pool: p, addr: addr}
	if p.proxyProtocol {
		if err := writeProxyHeader(conn, client.RemoteAddr(), client.LocalAddr()); err != nil {
			b.Close()
			return Backend{}, err
		}
	}
	return b, nil
}

// Read reads what the backend says.
func (b Backend) Read(buf []byte) (int, error) { return b.conn.Read(buf) }

// SetReadDeadline bounds the next Read.
func (b Backend) SetReadDeadline(t time.Time) error { return b.conn.SetReadDeadline(t) }

// Close closes a backend connection nobody will use and frees its slot.
func (b Backend) Close() {
	_ = b.conn.Close()
	b.pool.Release(b.addr)
}

// Proxy runs the session between client and b until both directions are
// done, then closes both and frees b's slot. first -- what the backend already
// said, read while the entrypoint waited to see who would speak first --
// reaches the client before anything else.
func (b Backend) Proxy(client net.Conn, first []byte) {
	defer client.Close()
	defer b.Close()
	if len(first) > 0 {
		if _, err := client.Write(first); err != nil {
			return
		}
	}
	client, err := takeReadAhead(client, b.conn)
	if err != nil {
		return
	}
	pipeHalfClose(client, b.conn)
}
