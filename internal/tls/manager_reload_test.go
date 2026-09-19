// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/acme/autocert"
)

// InvalidateTLS rebuilds the manager's Config from the store on every TLS
// change and hands it to UpdateConfig. That Config carries no HostPolicy and
// no Cache: both are runtime wiring installed by the server through
// SetHostPolicy and SetCache. If UpdateConfig lets the rebuilt Config replace
// them, the next ACME initialisation runs with a nil HostPolicy — and autocert
// treats a nil HostPolicy as "issue for every host", so any SNI name a client
// sends becomes a certificate order against the CA's rate limits.
func TestManager_UpdateConfigKeepsHostPolicyAndCache(t *testing.T) {
	cfg := Config{
		Enabled:  true,
		CacheDir: t.TempDir(),
		Acme:     AcmeConfig{Enabled: true, Email: "ops@example.com"},
	}
	m := NewManager(cfg)

	rejected := errors.New("host not authorized for ACME")
	m.SetHostPolicy(func(context.Context, string) error { return rejected })
	m.SetCache(autocert.DirCache(t.TempDir()))
	if _, err := m.GetTLSConfig(); err != nil {
		t.Fatalf("initial GetTLSConfig: %v", err)
	}

	// What the invalidator does after every certificate, option or global change.
	m.UpdateConfig(cfg)
	if _, err := m.GetTLSConfig(); err != nil {
		t.Fatalf("GetTLSConfig after UpdateConfig: %v", err)
	}

	m.mu.RLock()
	acme := m.acme
	m.mu.RUnlock()
	if acme == nil {
		t.Fatal("ACME manager not initialised")
	}
	if acme.HostPolicy == nil {
		t.Fatal("UpdateConfig dropped the host policy: autocert with a nil HostPolicy " +
			"orders a certificate for every host name a client presents")
	}
	if err := acme.HostPolicy(context.Background(), "attacker.example"); !errors.Is(err, rejected) {
		t.Fatalf("host policy replaced: got %v, want %v", err, rejected)
	}
	if m.config.Cache == nil {
		t.Fatal("UpdateConfig dropped the ACME cache installed by SetCache")
	}
}

// The global TLS config has the same fail-open shape as the per-route one: a
// verifying client-auth mode whose authorities cannot be read leaves ClientCAs
// nil, which crypto/tls resolves to the system roots. RequireAndVerify is
// already refused at startup; VerifyClientCertIfGiven must not silently verify
// against the public PKI either.
func TestManager_VerifyIfGivenWithoutLoadableCAs_FailsClosed(t *testing.T) {
	m := NewManager(Config{
		Enabled:        true,
		ClientAuthType: "VerifyClientCertIfGiven",
		ClientAuthorities: []ClientAuthorityConfig{{
			ID: "ca-missing", CaFile: filepath.Join(t.TempDir(), "does-not-exist.pem"),
		}},
	})
	cfg, err := m.GetTLSConfig()
	if err != nil {
		// Refusing to start is an acceptable fail-closed answer too.
		return
	}
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("ClientAuth=%v, want VerifyClientCertIfGiven", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatal("VerifyClientCertIfGiven with ClientCAs=nil: presented client certificates " +
			"would be verified against the system roots instead of the configured authorities")
	}
}
