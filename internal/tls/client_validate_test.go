// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tls

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/testutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func writeClientPair(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	cert, err := testutil.GenerateCert([]string{"client.test"})
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	if err := testutil.SaveCertToPEM(cert, certFile, keyFile); err != nil {
		t.Fatalf("save certificate: %v", err)
	}
	return certFile, keyFile
}

// Each of these was accepted, and the proxy then logged the failure and
// connected without the certificate or CA it was given.
func TestValidateClientConfigRefusesWhatTheProxyCannotBuild(t *testing.T) {
	cert, key := writeClientPair(t)
	missing := filepath.Join(t.TempDir(), "missing.pem")
	notPEM := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	byHeader := gateonv1.TlsClientCertSelectionStrategy_TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HEADER
	byHost := gateonv1.TlsClientCertSelectionStrategy_TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HOST
	for _, tc := range []struct {
		name string
		cfg  *gateonv1.TlsClientConfig
		says string
	}{
		{"a missing client certificate",
			&gateonv1.TlsClientConfig{Enabled: true, CertFile: missing, KeyFile: key}, "client certificate"},
		{"a key with no certificate",
			&gateonv1.TlsClientConfig{Enabled: true, KeyFile: key}, "both a client certificate and its key"},
		{"a missing CA file",
			&gateonv1.TlsClientConfig{Enabled: true, CaFile: missing}, "CA file"},
		{"a CA file that is not PEM",
			&gateonv1.TlsClientConfig{Enabled: true, CaFile: notPEM}, "CA certificate"},
		{"identities under the static strategy",
			&gateonv1.TlsClientConfig{Enabled: true, CertIdentities: []*gateonv1.TlsClientIdentity{
				{CertFile: cert, KeyFile: key, MatchHeader: "X-T"}}}, "static strategy"},
		{"an identity with no key",
			&gateonv1.TlsClientConfig{Enabled: true, CertSelectionStrategy: byHeader,
				CertIdentities: []*gateonv1.TlsClientIdentity{{Id: "a", CertFile: cert, MatchHeader: "X-T"}}},
			"identity a: needs both"},
		{"a by-header identity with no header",
			&gateonv1.TlsClientConfig{Enabled: true, CertSelectionStrategy: byHeader,
				CertIdentities: []*gateonv1.TlsClientIdentity{{CertFile: cert, KeyFile: key}}},
			"identity #1: matches no header"},
		{"a by-host identity with no host",
			&gateonv1.TlsClientConfig{Enabled: true, CertSelectionStrategy: byHost,
				CertIdentities: []*gateonv1.TlsClientIdentity{{CertFile: cert, KeyFile: key}}},
			"matches no host"},
		{"an identity whose key does not load",
			&gateonv1.TlsClientConfig{Enabled: true, CertSelectionStrategy: byHost,
				CertIdentities: []*gateonv1.TlsClientIdentity{
					{Id: "b", CertFile: cert, KeyFile: missing, MatchHosts: []string{"a.test"}}}},
			"identity b: failed to load"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateClientConfig(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("err = %v, want one saying %q", err, tc.says)
			}
		})
	}
}

func TestValidateClientConfigAcceptsWhatTheProxyBuilds(t *testing.T) {
	cert, key := writeClientPair(t)
	for _, cfg := range []*gateonv1.TlsClientConfig{
		nil,
		{Enabled: false, CertFile: "/nowhere.pem"},
		{Enabled: true},
		{Enabled: true, CertFile: cert, KeyFile: key, CaFile: cert},
		{Enabled: true, CertSelectionStrategy: gateonv1.TlsClientCertSelectionStrategy_TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HOST,
			CertIdentities: []*gateonv1.TlsClientIdentity{{CertFile: cert, KeyFile: key, MatchHosts: []string{"a.test"}}}},
		{Enabled: true, CertSelectionStrategy: gateonv1.TlsClientCertSelectionStrategy_TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HEADER,
			CertIdentities: []*gateonv1.TlsClientIdentity{{CertFile: cert, KeyFile: key, MatchHeader: "X-Tenant"}}},
	} {
		if err := ValidateClientConfig(cfg); err != nil {
			t.Errorf("%v refused: %v", cfg, err)
		}
	}
}
