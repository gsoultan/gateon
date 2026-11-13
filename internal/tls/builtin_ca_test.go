// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tls

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/tls/builtinca"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const eccRef = builtinca.Prefix + "cloudflare-origin-ca-ecc"

// Naming a built-in CA as a certificate's ca_file appends it to the served
// chain, exactly as a downloaded copy of the same file would.
func TestLoadCertificateAppendsBuiltinCA(t *testing.T) {
	certFile, keyFile := writeClientPair(t)
	m := NewManager(Config{})

	cert, _, err := m.LoadCertificate(certFile, keyFile, eccRef)
	if err != nil {
		t.Fatalf("LoadCertificate with %s: %v", eccRef, err)
	}
	if len(cert.Certificate) != 2 {
		t.Fatalf("chain has %d certificates, want leaf + built-in CA", len(cert.Certificate))
	}
	ca, err := x509.ParseCertificate(cert.Certificate[1])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ca.Subject.String(), "CloudFlare Origin SSL ECC Certificate Authority") {
		t.Fatalf("appended %q, want the Cloudflare ECC origin CA", ca.Subject)
	}
	if _, err := m.ValidateCertificateFiles(certFile, keyFile, eccRef); err != nil {
		t.Fatalf("ValidateCertificateFiles with %s: %v", eccRef, err)
	}
}

// A client authority naming the Authenticated Origin Pulls CA builds a
// client-CA pool, which is what verifies Cloudflare's client certificate.
func TestClientAuthorityFromBuiltinCA(t *testing.T) {
	m := NewManager(Config{})
	pool, err := m.LoadCA(builtinca.Prefix + "cloudflare-origin-pull-ca")
	if err != nil || pool == nil {
		t.Fatalf("LoadCA(origin pull) = %v, %v", pool, err)
	}
}

// Backend TLS can trust a built-in CA too: an origin serving a Cloudflare
// origin certificate is verified against it.
func TestClientConfigTrustsBuiltinCA(t *testing.T) {
	cfg, err := CreateTLSClientConfig(&gateonv1.TlsClientConfig{Enabled: true, CaFile: eccRef})
	if err != nil {
		t.Fatalf("CreateTLSClientConfig: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs not set from the built-in CA")
	}
}

// A reference that names no built-in CA fails even when a file with exactly
// that name sits where a relative ca_file would be looked up. Resolving it as
// a path would let whoever can write that directory choose the trust anchor.
func TestUnknownBuiltinRefIsNeverReadAsAFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	ref := builtinca.Prefix + "not-a-ca"
	if err := os.WriteFile(filepath.Join(dir, ref), []byte(readPEM(t, eccRef)), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(Config{})
	if _, err := m.LoadCAData(ref); err == nil {
		t.Fatal("LoadCAData read a file for an unknown built-in reference")
	}
	if _, err := CreateTLSClientConfig(&gateonv1.TlsClientConfig{Enabled: true, CaFile: ref}); err == nil {
		t.Fatal("CreateTLSClientConfig read a file for an unknown built-in reference")
	}
}

func readPEM(t *testing.T, ref string) string {
	t.Helper()
	data, err := builtinca.Read(ref)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// An expired or soon-expiring CA shows up in the certificate's validation
// warnings, which is what the dashboard displays for it.
func TestCAExpiryWarnings(t *testing.T) {
	a, _ := builtinca.Lookup(eccRef)
	ca, err := a.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(readPEM(t, eccRef))
	cases := []struct {
		name string
		now  time.Time
		want string
	}{
		{"well before expiry", ca.NotAfter.AddDate(-1, 0, 0), ""},
		{"inside the window", ca.NotAfter.AddDate(0, 0, -30), "expires on"},
		{"after expiry", ca.NotAfter.AddDate(0, 0, 1), "expired on"},
	}
	for _, tc := range cases {
		got := caExpiryWarnings(data, tc.now)
		switch {
		case tc.want == "" && len(got) != 0:
			t.Errorf("%s: unexpected warning %q", tc.name, got)
		case tc.want != "" && (len(got) != 1 || !strings.Contains(got[0], tc.want)):
			t.Errorf("%s: got %q, want one warning containing %q", tc.name, got, tc.want)
		}
	}
}
