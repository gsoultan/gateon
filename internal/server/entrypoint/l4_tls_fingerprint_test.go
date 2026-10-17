// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/security/identity"
)

// The TLS handshake records each connection's fingerprint in a table bounded
// at 65,536 entries, and only the HTTP entrypoint's ConnState hook removed
// them. A TLS-terminating TCP entrypoint's sessions left theirs behind, so
// every session took a slot for good and, once the table was full, no new
// connection anywhere was fingerprinted.
func TestATLSTerminatingL4SessionRemovesItsFingerprintWhenItEnds(t *testing.T) {
	backend, stopBackend := serveBackend(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	t.Cleanup(stopBackend)
	serverTLS, clientTLS := selfSignedTLS(t)
	serverTLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		identity.SetFingerprints(hello.Conn, identity.Fingerprints{JA4: "t13d-test"})
		return nil, nil
	}
	addr, stop := l4Entrypoint(t, backend, serverTLS)
	t.Cleanup(stop)

	c, err := tls.Dial("tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	client := c.LocalAddr().String()
	_ = echoed(t, c, "hello\n")
	if identity.GetFingerprintsByAddr(client).JA4 == "" {
		t.Fatal("the session's fingerprint was never recorded; the rest proves nothing")
	}
	_ = c.Close()
	stop() // returns once every session's goroutine has

	if f := identity.GetFingerprintsByAddr(client); f.JA4 != "" {
		t.Errorf("the fingerprint of an ended TLS L4 session from %s is still in the table", client)
	}
}
