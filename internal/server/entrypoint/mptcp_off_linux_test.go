// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package entrypoint

import (
	"context"
	"crypto/tls"
	"net"
	"reflect"
	"syscall"
	"testing"
)

// Since Go 1.24, net.Listen("tcp") opens an MPTCP socket wherever the kernel
// allows it. Nobody asked for that here: no Gateon feature uses MPTCP, and the
// public root exploit for CVE-2026-98432 was demonstrated against exactly such
// a listener. `godebug multipathtcp=0` in go.mod turns the default off for the
// binary and its tests; these check that every TCP listen path the gateway
// uses -- the HTTP and management entrypoints' net.Listen, and both arms of
// the L4 entrypoint -- comes out as plain TCP.

const ipprotoMPTCP = 262 // IPPROTO_MPTCP, linux/in.h

func socketProtocol(t *testing.T, l net.Listener) int {
	t.Helper()
	sc, ok := l.(*net.TCPListener)
	if !ok {
		t.Fatalf("listener %T is not a *net.TCPListener", l)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var proto int
	var serr error
	if err := rc.Control(func(fd uintptr) {
		proto, serr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PROTOCOL)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if serr != nil {
		t.Fatalf("getsockopt SO_PROTOCOL: %v", serr)
	}
	return proto
}

// requireMPTCPKernel skips where the kernel cannot open MPTCP at all: there
// every listener is plain TCP whatever the setting, and the test would pass
// without proving anything.
func requireMPTCPKernel(t *testing.T) {
	t.Helper()
	var lc net.ListenConfig
	lc.SetMultipathTCP(true)
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	if socketProtocol(t, l) != ipprotoMPTCP {
		t.Skip("kernel does not offer MPTCP (net.mptcp.enabled=0 or not built in)")
	}
}

// unwrapTLS returns the TCP listener tls.Listen opened. Its wrapper is
// unexported but embeds net.Listener, which reflection may read.
func unwrapTLS(t *testing.T, l net.Listener) net.Listener {
	t.Helper()
	if _, ok := l.(*net.TCPListener); ok {
		return l
	}
	v := reflect.ValueOf(l)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	f := v.FieldByName("Listener")
	if !f.IsValid() || !f.CanInterface() {
		t.Fatalf("cannot reach the TCP listener inside %T", l)
	}
	inner, ok := f.Interface().(net.Listener)
	if !ok {
		t.Fatalf("%T.Listener is not a net.Listener", l)
	}
	return inner
}

func TestGatewayListenersAreNotMPTCP(t *testing.T) {
	requireMPTCPKernel(t)

	plain := &tcpServer{plaintext: true}
	tlsSrv := &tcpServer{deps: &Deps{TLSConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Never called: the test only binds. tls.Listen refuses a config
		// that could not serve a handshake.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil },
	}}}
	cases := []struct {
		name   string
		listen func() (net.Listener, error)
	}{
		{"net.Listen (HTTP and management entrypoints)", func() (net.Listener, error) {
			return net.Listen("tcp", "127.0.0.1:0")
		}},
		{"L4 entrypoint, plaintext", func() (net.Listener, error) { return plain.listen("127.0.0.1:0") }},
		{"L4 entrypoint, TLS", func() (net.Listener, error) { return tlsSrv.listen("127.0.0.1:0") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, err := c.listen()
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() { _ = l.Close() }()
			if p := socketProtocol(t, unwrapTLS(t, l)); p == ipprotoMPTCP {
				t.Fatalf("listener is MPTCP (SO_PROTOCOL %d); the godebug multipathtcp=0 default is not in force", p)
			}
		})
	}
}
