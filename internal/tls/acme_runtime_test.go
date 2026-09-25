// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tls

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/acme/autocert"
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

// A change of ACME email or CA server waited for a restart: the autocert
// manager, built once, kept its account and directory, and could not simply
// be replaced because autocert has no way to stop the renewal timers it has
// scheduled -- a replaced manager would go on renewing from the old CA. The
// running manager is now retired instead: its way to the CA is closed, and a
// new one is built for the new account.
func TestChangingTheACMEAccountTakesEffectWithoutARestart(t *testing.T) {
	oldCA, oldHits := countingCA(t)
	newCA, newHits := countingCA(t)
	m := NewManager(Config{Enabled: true, Acme: AcmeConfig{Enabled: true, CAServer: oldCA}})
	m.SetCache(autocert.DirCache(t.TempDir()))
	m.SetHostPolicy(func(context.Context, string) error { return nil })
	if _, err := m.GetTLSConfig(); err != nil {
		t.Fatalf("GetTLSConfig: %v", err)
	}

	_, _ = m.GetCertificate(ecdsaHelloFor("one.example.test"))
	if oldHits.Load() == 0 {
		t.Fatal("control: issuing a certificate never asked the configured CA")
	}
	m.mu.RLock()
	retired := m.acme
	m.mu.RUnlock()

	m.UpdateConfig(Config{Enabled: true, Acme: AcmeConfig{Enabled: true, CAServer: newCA}})
	_, _ = m.GetCertificate(ecdsaHelloFor("two.example.test"))
	if newHits.Load() == 0 {
		t.Fatal("after the CA server changed, a new certificate was still ordered from the old one")
	}

	before := oldHits.Load()
	_, _ = retired.GetCertificate(ecdsaHelloFor("three.example.test"))
	if oldHits.Load() != before {
		t.Fatal("the retired ACME manager still reached its CA; its renewals would too")
	}
}

// countingCA is an ACME directory that answers every request 404 -- which the
// acme client does not retry -- and counts them.
func countingCA(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.NotFound(w, nil)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/directory", &hits
}
