// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// readAheadClient stands in for the TCP entrypoint's inspected connection: its
// first bytes were read before the proxy saw it, and Read replays them first.
type readAheadClient struct {
	net.Conn
	pending []byte
}

func (c *readAheadClient) Read(b []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func (c *readAheadClient) ReadAhead() ([]byte, net.Conn) {
	pending := c.pending
	c.pending = nil
	return pending, c.Conn
}

// proxiedPair runs ProxyTCP for one connection whose first bytes, pending, were
// read ahead, towards a backend running handle. It returns the client's end
// and a channel closed when ProxyTCP has returned.
func proxiedPair(t *testing.T, pending string, proxyProtocol bool, handle func(net.Conn)) (net.Conn, <-chan struct{}) {
	t.Helper()
	backend := listenLoopback(t)
	handled := make(chan struct{})
	go func() {
		defer close(handled)
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		handle(c)
	}()
	front := listenLoopback(t)
	client, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatalf("dial front: %v", err)
	}
	accepted, err := front.Accept()
	if err != nil {
		_ = client.Close()
		t.Fatalf("accept front: %v", err)
	}
	pool := NewTCPBackendPool([]string{backend.Addr().String()}, "round_robin", 10000, 1000, proxyProtocol)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pool.ProxyTCP(context.Background(), &readAheadClient{Conn: accepted, pending: []byte(pending)})
	}()
	// The client closes first: a session the proxy failed to end on its own
	// still ends, so a failing test reports instead of hanging.
	t.Cleanup(func() {
		_ = client.Close()
		<-done
		_ = backend.Close() // ends an Accept the proxy never reached
		<-handled
	})
	return client, done
}

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// TestProxyTCPTellsAReadAheadClientWhenTheBackendHangsUp is the half-close the
// inspected connection lost.
//
// When the backend finishes, ProxyTCP half-closes the client so it reads EOF.
// It found CloseWrite by asserting on the connection it was handed, and the
// entrypoint hands it a wrapper whose method set has no CloseWrite, so a
// backend that answers and hangs up -- whois, finger, a server-closes-first
// response -- left the client waiting for more, and the session open, until
// the client gave up on its own.
func TestProxyTCPTellsAReadAheadClientWhenTheBackendHangsUp(t *testing.T) {
	client, _ := proxiedPair(t, "", false, func(c net.Conn) {
		if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
			return
		}
		_, _ = io.WriteString(c, "bye\n") // answer, then hang up
	})
	if _, err := io.WriteString(client, "hi\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("the backend answered %q and hung up, but the client was never told: %v "+
			"(the proxy half-closes only a connection whose own type has CloseWrite)", got, err)
	}
	if string(got) != "bye\n" {
		t.Errorf("client read %q, want %q", got, "bye\n")
	}
}

// TestProxyTCPDeliversReadAheadBytesFirst: the bytes the entrypoint read to
// identify the protocol reach the backend before the rest of the stream, and
// after the PROXY header when there is one -- whichever way the proxy moves
// them.
func TestProxyTCPDeliversReadAheadBytesFirst(t *testing.T) {
	for _, proxyProtocol := range []bool{false, true} {
		name := "plain"
		if proxyProtocol {
			name = "proxy-protocol"
		}
		t.Run(name, func(t *testing.T) {
			received := make(chan string, 1)
			client, _ := proxiedPair(t, "SSH-2.0-", proxyProtocol, func(c net.Conn) {
				b, _ := io.ReadAll(c)
				received <- string(b)
			})
			if _, err := io.WriteString(client, "OpenSSH_9.6\r\n"); err != nil {
				t.Fatalf("write: %v", err)
			}
			if tc, ok := client.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
			got := <-received
			rest := got
			if proxyProtocol {
				header, after, found := strings.Cut(got, "\r\n")
				if !found || !strings.HasPrefix(header, "PROXY TCP4 127.0.0.1 127.0.0.1 ") {
					t.Fatalf("backend received %q, want a PROXY header first", got)
				}
				rest = after
			}
			if rest != "SSH-2.0-OpenSSH_9.6\r\n" {
				t.Errorf("backend received %q after any header, want the read-ahead bytes and then the rest in order", rest)
			}
		})
	}
}
