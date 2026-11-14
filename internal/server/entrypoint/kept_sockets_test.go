// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build unix

package entrypoint

import (
	"crypto/tls"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/gsoultan/gateon/internal/server/sockets"
)

// keptTCP is what the service manager holds after a gateway bound addr and
// exited: the socket, still listening, with nobody accepting from it.
func keptTCP(t *testing.T) (fd int, addr string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f, err := l.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	addr = l.Addr().String()
	_ = l.Close()
	fd, err = syscall.Dup(int(f.Fd()))
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	return fd, addr
}

// TestATCPEntrypointServesTheConnectionThatArrivedWhileItWasRestarting holds
// the entrypoint to the store: the socket kept across the restart is the one
// it accepts from, so the client that connected in between is served.
func TestATCPEntrypointServesTheConnectionThatArrivedWhileItWasRestarting(t *testing.T) {
	fd, addr := keptTCP(t)
	client, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("connecting while no gateway runs: %v", err)
	}
	defer func() { _ = client.Close() }()
	if _, err := client.Write([]byte("waiting")); err != nil {
		t.Fatal(err)
	}

	s := &tcpServer{plaintext: true, deps: &Deps{Sockets: sockets.Adopt([]int{fd}, []string{"kept"})}}
	l, err := s.listen(addr)
	if err != nil {
		t.Fatalf("an entrypoint whose socket was kept could not listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	_ = l.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("the connection made during the restart was not there: %v", err)
	}
	defer func() { _ = conn.Close() }()
	got := make([]byte, 7)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "waiting" {
		t.Fatalf("read %q (%v)", got, err)
	}
}

// TestATLSEntrypointTerminatesTLSOnTheKeptSocket: keeping the socket must
// not turn a TLS entrypoint into a plaintext one.
func TestATLSEntrypointTerminatesTLSOnTheKeptSocket(t *testing.T) {
	fd, addr := keptTCP(t)
	s := &tcpServer{deps: &Deps{Sockets: sockets.Adopt([]int{fd}, nil), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}}
	l, err := s.listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if _, plain := l.(*net.TCPListener); plain {
		t.Fatal("a TLS entrypoint is accepting plaintext from the kept socket")
	}
	if l.Addr().String() != addr {
		t.Fatalf("listening on %s, want the kept %s", l.Addr(), addr)
	}
}

// TestAnHTTP3EntrypointListensOnTheKeptSocketAndClosesIt: quic-go leaves a
// socket it was handed open when its listener closes, so the entrypoint has
// to close it or shutdown would leak it.
func TestAnHTTP3EntrypointListensOnTheKeptSocketAndClosesIt(t *testing.T) {
	first, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f, err := first.File()
	if err != nil {
		t.Fatal(err)
	}
	addr := first.LocalAddr().String()
	_ = first.Close()
	fd, err := syscall.Dup(int(f.Fd()))
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}

	ln, err := listenQUIC(sockets.Adopt([]int{fd}, nil), addr, &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if ln.Addr().String() != addr {
		t.Fatalf("QUIC is listening on %s, want the kept %s", ln.Addr(), addr)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	// Nothing holds the port any more, so it can be bound again.
	again, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("the socket outlived its listener: %v", err)
	}
	_ = again.Close()
}

// TestEveryListenerIsOpenedThroughTheStore: a listener bound with the net
// package directly is one a restart closes, and nothing else would say so.
func TestEveryListenerIsOpenedThroughTheStore(t *testing.T) {
	direct := regexp.MustCompile(`\b(net\.Listen(TCP|UDP|Packet)?|tls\.Listen|quic\.ListenAddr(Early)?)\(`)
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no source files found: %v", err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file) // #nosec G304 -- this package's own source
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if direct.MatchString(line) && !strings.HasPrefix(strings.TrimSpace(line), "//") {
				t.Errorf("%s:%d binds a listener without the socket store: %s", file, i+1, strings.TrimSpace(line))
			}
		}
	}
}
