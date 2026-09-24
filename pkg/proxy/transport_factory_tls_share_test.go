// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"crypto/tls"
	"net/http"
	"testing"
)

// TestHealthCheckTransportDoesNotEditTheSharedTLSConfig initialises the
// health-check transport and checks the factory's base TLS config is left as it
// was.
//
// net/http's Transport edits its TLSClientConfig in place when it sets up
// HTTP/2 ("Server.ServeTLS clones the tls.Config before modifying it.
// Transport doesn't."). The health-check transport was handed the factory's
// base config itself, so its first request or CloseIdleConnections rewrote
// NextProtos on the config every other backend transport is cloned from —
// a data race with those clones, and an ALPN list nobody configured leaking
// into every transport built after it.
func TestHealthCheckTransportDoesNotEditTheSharedTLSConfig(t *testing.T) {
	base := &tls.Config{MinVersion: tls.VersionTLS12}
	f := newBackendTransportFactory(base, nil, nil)

	ht, ok := f.HealthCheckTransport().(*http.Transport)
	if !ok {
		t.Fatalf("health-check transport is %T, want *http.Transport", f.HealthCheckTransport())
	}
	ht.CloseIdleConnections() // runs net/http's one-time HTTP/2 setup

	if len(base.NextProtos) != 0 {
		t.Fatalf("the factory's base TLS config was edited: NextProtos = %v", base.NextProtos)
	}
}
