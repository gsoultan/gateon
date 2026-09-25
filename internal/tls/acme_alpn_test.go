// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tls

import (
	"slices"
	"testing"

	"golang.org/x/crypto/acme"
)

// TestACMEConfigOffersTheValidationProtocol builds the gateway's TLS config
// with ACME on. autocert answers a TLS-ALPN-01 validation on acme-tls/1, and
// crypto/tls negotiates ALPN from this list before it asks for a certificate,
// so a list without it refused the CA's validation handshake with "no
// application protocol" -- the config set h2 and http/1.1 over the list
// autocert's own config carried.
func TestACMEConfigOffersTheValidationProtocol(t *testing.T) {
	m := NewManager(Config{Enabled: true, CacheDir: t.TempDir(), Acme: AcmeConfig{Enabled: true, Email: "ops@example.com"}})
	cfg, err := m.GetTLSConfig()
	if err != nil {
		t.Fatalf("GetTLSConfig: %v", err)
	}
	for _, want := range []string{"h2", "http/1.1", acme.ALPNProto} {
		if !slices.Contains(cfg.NextProtos, want) {
			t.Fatalf("NextProtos = %v, missing %q", cfg.NextProtos, want)
		}
	}
}
