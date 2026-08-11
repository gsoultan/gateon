// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"crypto/tls"
	"net"
	"testing"
)

type mockConn struct {
	net.Conn
	addr string
}

func (c *mockConn) RemoteAddr() net.Addr {
	return &mockAddr{addr: c.addr}
}

type mockAddr struct {
	net.Addr
	addr string
}

func (a *mockAddr) String() string {
	return a.addr
}

func (a *mockAddr) Network() string {
	return "tcp"
}

func TestFingerprintRegistry(t *testing.T) {
	rawConn := &mockConn{addr: "1.2.3.4:55555"}
	tlsConn := &mockConn{addr: "1.2.3.4:55555"}

	fp := Fingerprints{JA4: "ja4"}

	SetFingerprints(rawConn, fp)
	defer RemoveFingerprints(rawConn)

	got := GetFingerprints(tlsConn)
	if got != fp {
		t.Errorf("Expected %+v, got %+v", fp, got)
	}

	RemoveFingerprints(tlsConn)
	gotAfter := GetFingerprints(rawConn)
	if gotAfter.JA4 != "" {
		t.Errorf("Fingerprints not removed")
	}
}

func TestCalcFingerprints(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256},
		ServerName:        "test.com",
	}

	fp := CalcFingerprints(hello)
	if fp.JA4 == "" {
		t.Fatal("Fingerprints should not be empty")
	}
}
