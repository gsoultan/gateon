// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// A route's client-certificate requirement is enforced during the TLS
// handshake, and the handshake picks its configuration from the SNI name. The
// route that serves the request is picked afterwards, from the Host header. The
// two are chosen by different values the client writes, so a client could
// complete the handshake under a route that asks for no certificate and then
// name the mTLS route in Host -- domain fronting. With a SAN or wildcard
// certificate covering both names, which is the ordinary shape, nothing about
// the connection looks wrong.
//
// This is the attack the TLS option comment names as the use case: Cloudflare
// Authenticated Origin Pulls, where the client certificate is what proves a
// request came through Cloudflare rather than straight to the origin.
func TestSNIHostMismatch_MTLSRouteRefusesDomainFronting(t *testing.T) {
	resetTLSCaches(t)
	const (
		publicHost = "public.example.com"
		secureHost = "secure.example.com"
	)
	gw := newFrontingGateway(t, []string{publicHost, secureHost},
		&gateonv1.Route{Id: "r-public", ServiceId: "svc-public", Type: "http",
			Rule: "Host(`" + publicHost + "`)", Tls: &gateonv1.RouteTLSConfig{CertificateIds: []string{"cert-san"}}},
		&gateonv1.Route{Id: "r-secure", ServiceId: "svc-secure", Type: "http",
			Rule: "Host(`" + secureHost + "`)",
			Tls:  &gateonv1.RouteTLSConfig{CertificateIds: []string{"cert-san"}, OptionId: "opt-mtls"}},
	)

	// Controls first, so the attack below cannot pass for the wrong reason.
	// The public route works over its own name...
	if status, body := gw.get(t, publicHost, publicHost, nil); status != http.StatusOK || body != "public" {
		t.Fatalf("control: public route = %d %q, want 200 \"public\"", status, body)
	}
	// ...and the secure route's handshake really does demand a certificate:
	// without the fronting trick, a client with none cannot get in at all.
	if _, _, err := gw.do(t, secureHost, secureHost, nil); err == nil {
		t.Fatal("control: a handshake naming the mTLS route without a client certificate succeeded; " +
			"the route is not enforcing mTLS, so this test would prove nothing")
	}

	// The attack: handshake as the public route, ask for the secure one.
	status, body, err := gw.do(t, publicHost, secureHost, nil)
	if err != nil {
		t.Fatalf("fronted request failed before reaching the gateway: %v", err)
	}
	if hits := gw.secureHits.Load(); hits != 0 || status == http.StatusOK {
		t.Fatalf("SNI %q with Host %q and no client certificate reached the mTLS route's backend "+
			"(status %d, body %q, backend hits %d): the certificate requirement was enforced on the name "+
			"the handshake used, not on the route that served the request", publicHost, secureHost, status, body, hits)
	}
	if status != http.StatusMisdirectedRequest {
		t.Errorf("fronted request status = %d, want %d Misdirected Request so a legitimate client "+
			"that coalesced connections retries on a fresh one", status, http.StatusMisdirectedRequest)
	}

	// And the refusal must not cost legitimate mTLS clients anything.
	if status, body := gw.get(t, secureHost, secureHost, gw.clientCert); status != http.StatusOK || body != "secure" {
		t.Fatalf("a client presenting a valid certificate under the secure route's own name got %d %q, want 200 \"secure\"",
			status, body)
	}
}

// The same requirement, reached without fronting at all. When a route's own
// certificate cannot be loaded, the handshake does not fail: it moves on to the
// next route for that name, and uses that route's configuration -- which here
// asks for no client certificate. SNI and Host now agree, both naming the mTLS
// route, so a check that only compared names would pass it. The route still
// has to find the certificate its option requires on the connection.
func TestSNIHostMismatch_MTLSRouteWhoseCertFailsStillRequiresClientCert(t *testing.T) {
	resetTLSCaches(t)
	const secureHost = "secure.example.com"
	gw := newFrontingGateway(t, []string{secureHost},
		&gateonv1.Route{Id: "r-secure", ServiceId: "svc-secure", Type: "http", Priority: 10,
			Rule: "Host(`" + secureHost + "`)",
			Tls:  &gateonv1.RouteTLSConfig{CertificateIds: []string{"cert-missing"}, OptionId: "opt-mtls"}},
		&gateonv1.Route{Id: "r-static", ServiceId: "svc-public", Type: "http",
			Rule: "Host(`" + secureHost + "`) && PathPrefix(`/static`)",
			Tls:  &gateonv1.RouteTLSConfig{CertificateIds: []string{"cert-san"}}},
	)

	// Control: the handshake does complete without a certificate, because it
	// fell through to r-static's configuration. If it did not, the request
	// below could not reach the gateway and the test would prove nothing.
	status, body, err := gw.do(t, secureHost, secureHost, nil)
	if err != nil {
		t.Fatalf("control: expected the handshake to fall through to r-static and succeed: %v", err)
	}
	if hits := gw.secureHits.Load(); hits != 0 || status == http.StatusOK {
		t.Fatalf("a request with no client certificate reached r-secure's backend (status %d, body %q, hits %d): "+
			"its option requires a verified certificate, and the connection never presented one",
			status, body, hits)
	}
}

// frontingGateway is a TLS entrypoint wired the way run.go wires one: SetupSNI
// on the listener's config, and EntryPoint -> CreateBaseHandler ->
// HandleProxyOrLocal behind it.
type frontingGateway struct {
	addr       string
	serverCAs  *x509.CertPool
	clientCert *tls.Certificate
	secureHits atomic.Int64
}

// newFrontingGateway serves routes behind one SAN certificate for hosts
// ("cert-san"), with "cert-missing" naming a certificate that cannot be
// loaded, "opt-mtls" requiring a certificate from the test client CA, and
// services "svc-public" and "svc-secure" answering with their own names.
func newFrontingGateway(t *testing.T, hosts []string, routes ...*gateonv1.Route) *frontingGateway {
	t.Helper()
	gw := &frontingGateway{}
	dir := t.TempDir()

	certPath, keyPath, serverPool := writeSANServerCert(t, dir, hosts...)
	gw.serverCAs = serverPool
	caPath, clientCert := writeClientCAAndCert(t, dir)
	gw.clientCert = clientCert

	s, err := NewServer(
		WithRouteRegistry(config.NewRouteRegistry(filepath.Join(dir, "routes.json"))),
		WithServiceRegistry(config.NewServiceRegistry(filepath.Join(dir, "services.json"))),
		WithMiddlewareRegistry(config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json"))),
		WithTLSOptionRegistry(config.NewTLSOptionRegistry(filepath.Join(dir, "tls_options.json"))),
		WithGlobalRegistry(config.NewGlobalRegistry(filepath.Join(dir, "global.json"))),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.GlobalStore.Update(ctx, &gateonv1.GlobalConfig{Tls: &gateonv1.TlsConfig{
		Certificates: []*gateonv1.Certificate{
			{Id: "cert-san", CertFile: certPath, KeyFile: keyPath},
			{Id: "cert-missing", CertFile: filepath.Join(dir, "absent.pem"), KeyFile: filepath.Join(dir, "absent-key.pem")},
		},
		ClientAuthorities: []*gateonv1.ClientAuthority{{Id: "ca-internal", Name: "internal", CaFile: caPath}},
	}}))
	must(s.TLSOptStore.Update(ctx, &gateonv1.TLSOption{
		Id: "opt-mtls", Name: "mtls", ClientAuthType: "RequireAndVerifyClientCert",
		ClientAuthorityIds: []string{"ca-internal"},
	}))

	public := newBackend(t, "public", nil)
	secure := newBackend(t, "secure", &gw.secureHits)
	must(s.ServiceStore.Update(ctx, &gateonv1.Service{Id: "svc-public",
		WeightedTargets: []*gateonv1.Target{{Url: public.URL, Weight: 1}}}))
	must(s.ServiceStore.Update(ctx, &gateonv1.Service{Id: "svc-secure",
		WeightedTargets: []*gateonv1.Target{{Url: secure.URL, Weight: 1}}}))
	for _, rt := range routes {
		must(s.RouteStore.Update(ctx, rt))
	}

	tlsCfg := baseTLSConfig()
	SetupSNI(tlsCfg, gtls.NewManager(gtls.Config{}), SNIDeps{
		RouteStore: s.RouteStore, GlobalStore: s.GlobalStore, TLSOptStore: s.TLSOptStore,
	})

	mux := http.NewServeMux()
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.HandleProxyOrLocal(w, r, nil, nil, mux)
	})
	base := CreateBaseHandler(http.NotFoundHandler(), BaseHandlerDeps{
		ProxyHandler: proxyHandler, RouteStore: s.RouteStore, GlobalReg: s.GlobalStore,
	}, nil, mux)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler:           middleware.EntryPoint("websecure", "websecure", false)(base),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.ServeTLS(ln, "", "")
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})
	gw.addr = ln.Addr().String()
	return gw
}

// do sends one GET with the given SNI and Host, presenting cert if non-nil.
func (gw *frontingGateway) do(t *testing.T, sni, host string, cert *tls.Certificate) (int, string, error) {
	t.Helper()
	tlsCfg := &tls.Config{ServerName: sni, RootCAs: gw.serverCAs, MinVersion: tls.VersionTLS12}
	if cert != nil {
		tlsCfg.Certificates = []tls.Certificate{*cert}
	}
	tr := &http.Transport{TLSClientConfig: tlsCfg, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	req, err := http.NewRequest(http.MethodGet, "https://"+gw.addr+"/", nil)
	if err != nil {
		return 0, "", err
	}
	req.Host = host
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), err
}

func (gw *frontingGateway) get(t *testing.T, sni, host string, cert *tls.Certificate) (int, string) {
	t.Helper()
	status, body, err := gw.do(t, sni, host, cert)
	if err != nil {
		t.Fatalf("GET sni=%q host=%q: %v", sni, host, err)
	}
	return status, body
}

func newBackend(t *testing.T, name string, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		_, _ = io.WriteString(w, name)
	}))
	t.Cleanup(b.Close)
	return b
}

// writeSANServerCert writes one self-signed server certificate valid for every
// host given, and returns a pool that trusts it.
func writeSANServerCert(t *testing.T, dir string, hosts ...string) (certPath, keyPath string, pool *x509.CertPool) {
	t.Helper()
	key := mustECKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: mustSerial(t), Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	certPath = filepath.Join(dir, "server.pem")
	keyPath = filepath.Join(dir, "server-key.pem")
	writePEM(t, certPath, "CERTIFICATE", der)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	writePEM(t, keyPath, "EC PRIVATE KEY", keyDER)
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(parsed)
	return certPath, keyPath, pool
}

// writeClientCAAndCert writes a client CA bundle and returns it with a client
// certificate that CA issued.
func writeClientCAAndCert(t *testing.T, dir string) (caPath string, clientCert *tls.Certificate) {
	t.Helper()
	caKey := mustECKey(t)
	caTmpl := &x509.Certificate{
		SerialNumber: mustSerial(t), Subject: pkix.Name{CommonName: "Gateon Test Client CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, IsCA: true, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client CA: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse client CA: %v", err)
	}
	caPath = filepath.Join(dir, "client-ca.pem")
	writePEM(t, caPath, "CERTIFICATE", caDER)

	leafKey := mustECKey(t)
	leafTmpl := &x509.Certificate{
		SerialNumber: mustSerial(t), Subject: pkix.Name{CommonName: "origin-pull"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	return caPath, &tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

func mustECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func mustSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return serial
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
