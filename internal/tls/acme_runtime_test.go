// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tls

import (
	"crypto/tls"
	"strings"
	"testing"
)

// Without a host policy of its own the manager authorises its configured
// domains. It read them when the ACME manager was built, so a domain added
// by a later UpdateConfig was refused until a restart.
func TestACMEDomainsFollowUpdateConfig(t *testing.T) {
	const first, added = "first.example.test", "added.example.test"
	m := NewManager(Config{Enabled: true, Domains: []string{first},
		Acme: AcmeConfig{Enabled: true, CAServer: "http://127.0.0.1:1/directory"}})
	m.SetCache(cachedACMECert(t, first))
	if _, err := m.GetTLSConfig(); err != nil {
		t.Fatalf("GetTLSConfig: %v", err)
	}
	m.UpdateConfig(Config{Enabled: true, Domains: []string{first, added},
		Acme: AcmeConfig{Enabled: true, CAServer: "http://127.0.0.1:1/directory"}})

	hello := ecdsaHelloFor(added)
	if _, err := m.GetCertificate(hello); err == nil || strings.Contains(err.Error(), "not in whitelist") {
		t.Fatalf("a domain added by UpdateConfig was refused by the whitelist: %v", err)
	}
}

func ecdsaHelloFor(host string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:        host,
		CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedVersions: []uint16{tls.VersionTLS12},
	}
}
