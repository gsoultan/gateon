// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/testutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func writeIdentity(t *testing.T) (certFile, keyFile string) {
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

func tlsService(cfg *gateonv1.TlsClientConfig) *gateonv1.Service {
	return &gateonv1.Service{WeightedTargets: targets(1), TlsClientConfig: cfg}
}

// TestSaveRefusesBackendTLSTheProxyCannotBuild: each of these saved, and the
// proxy then logged the failure and connected without the certificate or CA,
// so a backend that requires mutual TLS refused every request while the
// service read as saved.
func TestSaveRefusesBackendTLSTheProxyCannotBuild(t *testing.T) {
	cert, key := writeIdentity(t)
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
		{"a client certificate that does not exist",
			&gateonv1.TlsClientConfig{Enabled: true, CertFile: missing, KeyFile: key}, "client certificate"},
		{"a certificate with no key",
			&gateonv1.TlsClientConfig{Enabled: true, CertFile: cert}, "both a client certificate and its key"},
		{"a CA file that is not PEM",
			&gateonv1.TlsClientConfig{Enabled: true, CaFile: notPEM}, "CA certificate"},
		{"identities under the static strategy, which never reads them",
			&gateonv1.TlsClientConfig{Enabled: true, CertIdentities: []*gateonv1.TlsClientIdentity{
				{Id: "a", CertFile: cert, KeyFile: key, MatchHeader: "X-T"}}}, "static strategy"},
		{"a by-header identity with no header",
			&gateonv1.TlsClientConfig{Enabled: true, CertSelectionStrategy: byHeader,
				CertIdentities: []*gateonv1.TlsClientIdentity{{Id: "a", CertFile: cert, KeyFile: key}}},
			"identity a: matches no header"},
		{"a by-host identity with no host",
			&gateonv1.TlsClientConfig{Enabled: true, CertSelectionStrategy: byHost,
				CertIdentities: []*gateonv1.TlsClientIdentity{{CertFile: cert, KeyFile: key}}},
			"identity #1: matches no host"},
		{"an identity whose key does not exist",
			&gateonv1.TlsClientConfig{Enabled: true, CertSelectionStrategy: byHost,
				CertIdentities: []*gateonv1.TlsClientIdentity{
					{Id: "b", CertFile: cert, KeyFile: missing, MatchHosts: []string{"a.test"}}}},
			"identity b: failed to load"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeServiceStore{services: map[string]*gateonv1.Service{}}
			s := NewService(store, &fakeRouteStore{updateErr: map[string]error{}}, &recordingInvalidator{}, nil)
			err := s.SaveService(t.Context(), tlsService(tc.cfg))
			if !errors.Is(err, ErrInvalidService) || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("err = %v, want ErrInvalidService saying %q", err, tc.says)
			}
			if len(store.services) != 0 {
				t.Fatal("a refused service was stored")
			}
		})
	}
}

// TestSaveKeepsBackendTLSTheProxyCanBuild: loadable files save, and a
// disabled config is not built by the proxy and so is not checked.
func TestSaveKeepsBackendTLSTheProxyCanBuild(t *testing.T) {
	cert, key := writeIdentity(t)
	for _, cfg := range []*gateonv1.TlsClientConfig{
		{Enabled: true, CertFile: cert, KeyFile: key, CaFile: cert},
		{Enabled: true, CertSelectionStrategy: gateonv1.TlsClientCertSelectionStrategy_TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HEADER,
			CertIdentities: []*gateonv1.TlsClientIdentity{{CertFile: cert, KeyFile: key, MatchHeader: "X-Tenant"}}},
		{Enabled: false, CertFile: "/nowhere.pem"},
	} {
		s := NewService(&fakeServiceStore{services: map[string]*gateonv1.Service{}},
			&fakeRouteStore{updateErr: map[string]error{}}, &recordingInvalidator{}, nil)
		if err := s.SaveService(t.Context(), tlsService(cfg)); err != nil {
			t.Errorf("%v refused: %v", cfg, err)
		}
	}
}
