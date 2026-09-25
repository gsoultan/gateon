// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/testutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// BY_HOST chooses the client certificate the gateway presents to a backend by
// the host the request was routed on. It read X-Forwarded-Host, which a client
// writes as easily as any other header: on the proxied path the rewrite
// happened to overwrite it first, but anything that selects from the inbound
// request -- a protocol upgrade -- let the client name the identity. And with
// no forwarded host it fell back to req.Host, which on an outbound request is
// the backend's own address.
func TestClientIdentityByHostIsTheRoutedHost(t *testing.T) {
	selector := &tlsClientIdentitySelector{
		strategy: gateonv1.TlsClientCertSelectionStrategy_TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HOST,
		identities: []tlsClientIdentity{
			{id: "shop", matchHosts: []string{"shop.example.com"}},
			{id: "admin", matchHosts: []string{"admin.example.com"}},
			{id: "backend", matchHosts: []string{"backend.internal"}},
		},
	}

	routed := httptest.NewRequest(http.MethodGet, "http://backend.internal/", nil)
	routed.Header.Set("X-Forwarded-Host", "admin.example.com")
	routed = routed.WithContext(request.WithState(routed.Context(), &request.RequestState{StrippedHost: "shop.example.com"}))
	if got := selector.Select(routed); got == nil || got.id != "shop" {
		t.Fatalf("a request routed on shop.example.com that names admin.example.com in X-Forwarded-Host "+
			"was given identity %v; it must be the routed host's, %q", identityID(got), "shop")
	}

	unrouted := httptest.NewRequest(http.MethodGet, "http://backend.internal/", nil)
	if got := selector.Select(unrouted); got != nil {
		t.Fatalf("a request with no routed host was given identity %q; with nothing the gateway "+
			"routed on there is no host to choose by, and the backend's own address is not one", got.id)
	}
}

// The transport a selected identity uses was cached under its id, so two
// identities with the same id -- or, the easy case, none -- shared one
// transport, and whichever was built first presented its certificate for both.
func TestClientIdentitiesWithoutIDsDoNotShareACertificate(t *testing.T) {
	dir := t.TempDir()
	aCert, aKey := writeClientCert(t, dir, "a.identity.test")
	bCert, bKey := writeClientCert(t, dir, "b.identity.test")
	selector, err := newTLSClientIdentitySelector(&gateonv1.TlsClientConfig{
		CertSelectionStrategy: gateonv1.TlsClientCertSelectionStrategy_TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HEADER,
		CertIdentities: []*gateonv1.TlsClientIdentity{
			{CertFile: aCert, KeyFile: aKey, MatchHeader: "X-Tenant", MatchHeaderValue: "a"},
			{CertFile: bCert, KeyFile: bKey, MatchHeader: "X-Tenant", MatchHeaderValue: "b"},
		},
	})
	if err != nil {
		t.Fatalf("load identities: %v", err)
	}
	f := newBackendTransportFactory(&tls.Config{MinVersion: tls.VersionTLS12}, nil, selector)
	s := newTargetState("https://backend:443", 1)

	for _, tenant := range []string{"a", "b"} {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		req.Header.Set("X-Tenant", tenant)
		tr, ok := f.TransportFor(s, req).(*http.Transport)
		if !ok {
			t.Fatalf("expected *http.Transport, got %T", f.TransportFor(s, req))
		}
		certs := tr.TLSClientConfig.Certificates
		want := tenant + ".identity.test"
		if len(certs) != 1 || certs[0].Leaf == nil || certs[0].Leaf.DNSNames[0] != want {
			t.Fatalf("tenant %q's transport presents %s, not its own certificate %s",
				tenant, presentedName(certs), want)
		}
	}
}

// A protocol upgrade dials the backend itself rather than through the
// transport, and it dialled with the service's static TLS config: a BY_HEADER
// or BY_HOST service presented no client certificate on any upgrade, so a
// backend that requires one refused every WebSocket.
func TestUpgradePresentsTheSelectedClientIdentity(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Answers without switching protocols, so the proxy relays this as an
		// ordinary response after dialling for the upgrade.
		_, _ = io.WriteString(w, presentedPeer(r))
	}))
	backend.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	backend.StartTLS()
	defer backend.Close()

	dir := t.TempDir()
	certFile, keyFile := writeClientCert(t, dir, "admin.identity.test")
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	if err := services.Update(context.Background(), &gateonv1.Service{
		Id:              "svc",
		WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}},
		TlsClientConfig: &gateonv1.TlsClientConfig{
			Enabled:               true,
			SkipVerify:            true,
			CertSelectionStrategy: gateonv1.TlsClientCertSelectionStrategy_TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HEADER,
			CertIdentities: []*gateonv1.TlsClientIdentity{{
				Id: "admin", CertFile: certFile, KeyFile: keyFile,
				MatchHeader: "X-Tenant", MatchHeaderValue: "admin",
			}},
		},
	}); err != nil {
		t.Fatalf("update service: %v", err)
	}
	ph := NewProxyHandler(&gateonv1.Route{Id: "ws", ServiceId: "svc"}, services)
	defer ph.Close()
	gw := httptest.NewServer(ph)
	defer gw.Close()

	for _, upgrade := range []string{"", "websocket"} {
		req, _ := http.NewRequest(http.MethodGet, gw.URL+"/socket", nil)
		req.Header.Set("X-Tenant", "admin")
		if upgrade != "" {
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", upgrade)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request (upgrade=%q): %v", upgrade, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if got := string(body); got != "admin.identity.test" {
			t.Fatalf("with Upgrade %q the backend saw client certificate %q; the service selects "+
				"%q for this request", upgrade, got, "admin.identity.test")
		}
	}
}

func presentedPeer(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "none"
	}
	return r.TLS.PeerCertificates[0].DNSNames[0]
}

func presentedName(certs []tls.Certificate) string {
	if len(certs) == 0 || certs[0].Leaf == nil {
		return "no certificate"
	}
	return certs[0].Leaf.DNSNames[0]
}

func identityID(id *tlsClientIdentity) string {
	if id == nil {
		return "<none>"
	}
	return id.id
}

func mustClientCert(t *testing.T, name string) tls.Certificate {
	t.Helper()
	cert, err := testutil.GenerateCert([]string{name})
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	return cert
}

func writeClientCert(t *testing.T, dir, name string) (certFile, keyFile string) {
	t.Helper()
	certFile = filepath.Join(dir, name+".crt")
	keyFile = filepath.Join(dir, name+".key")
	if err := testutil.SaveCertToPEM(mustClientCert(t, name), certFile, keyFile); err != nil {
		t.Fatalf("save certificate: %v", err)
	}
	return certFile, keyFile
}
