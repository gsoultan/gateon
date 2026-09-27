// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"context"
	"net"
)

// TCPProxy proxies a single TCP connection to a backend.
type TCPProxy interface {
	ProxyTCP(ctx context.Context, client net.Conn)
}

// ReadAheadConn is a connection whose first bytes were read before it reached
// the proxy: the TCP entrypoint reads them to tell SSH from RDP from HTTP.
//
// ReadAhead returns the bytes read but not yet delivered, and the connection
// they were read from, and hands both over: the caller sends the bytes on, and
// the wrapper will not return them from Read again. The proxy needs the
// connection underneath because the wrapper's type hides what it is -- a
// *net.TCPConn that splice(2) can move bytes to and from, and whose CloseWrite
// tells the client the backend has finished.
//
// It must return the connection the wrapper reads from, never one beneath a
// layer that transforms bytes: unwrapping a TLS connection would put
// ciphertext on the wire in place of the plaintext the backend expects.
type ReadAheadConn interface {
	net.Conn
	ReadAhead() (pending []byte, conn net.Conn)
}

// UDPProxy handles UDP packets for an entrypoint.
type UDPProxy interface {
	HandlePacket(conn *net.UDPConn, addr *net.UDPAddr, data []byte)
	Stop()
}
