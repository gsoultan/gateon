// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const acmeIssuedCN = "acme-issued"

// Turning the global ACME switch off did nothing until a restart: the base TLS
// config had ACME's GetCertificate fixed into it when the gateway started, and
// every per-handshake config is a clone of the base, so ACME went on answering
// ahead of the certificates configured to replace it.
func TestTurningGlobalACMEOffTakesEffectWithoutARestart(t *testing.T) {
	const host = "acme-off.example.test"
	f := newACMEFixture(t, &gateonv1.TlsConfig{
		Enabled: true, Domains: []string{host}, Acme: &gateonv1.AcmeConfig{Enabled: true},
	}, acmeCacheWithCert(t, host))

	if cn, err := servedCN(f.base, host); err != nil || cn != acmeIssuedCN {
		t.Fatalf("control: with ACME on the gateway served %q (err %v), not the ACME certificate", cn, err)
	}

	certFile, keyFile := createTempCertKey(t, host)
	f.save(t, &gateonv1.TlsConfig{
		Enabled: true, Domains: []string{host}, Acme: &gateonv1.AcmeConfig{Enabled: false},
		Certificates: []*gateonv1.Certificate{{Id: "manual", Name: "manual", CertFile: certFile, KeyFile: keyFile}},
	})
	if cn, err := servedCN(f.base, host); err != nil || cn == acmeIssuedCN {
		t.Fatalf("after turning ACME off and configuring a certificate, the gateway served %q (err %v); "+
			"ACME is still answering", cn, err)
	}
}

// Turning it on did take effect for the certificate, but not for the two
// things ACME needs besides: the acme-tls/1 protocol, which the CA's
// TLS-ALPN-01 validation negotiates and which the base config only carried if
// ACME was on at startup, and the domain whitelist, which the host policy
// captured at startup.
func TestTurningGlobalACMEOnTakesEffectWithoutARestart(t *testing.T) {
	const host = "acme-on.example.test"
	f := newACMEFixture(t, &gateonv1.TlsConfig{Enabled: true}, acmeCacheWithCert(t, host))

	if _, err := servedCN(f.base, host); err == nil {
		t.Fatal("control: with ACME off and no certificate the handshake succeeded")
	}

	const added = "added-later.example.test"
	f.save(t, &gateonv1.TlsConfig{
		Enabled: true, Domains: []string{host, added},
		Acme: &gateonv1.AcmeConfig{Enabled: true, CaServer: "http://127.0.0.1:1/directory"},
	})
	if cn, err := servedCN(f.base, host); err != nil || cn != acmeIssuedCN {
		t.Fatalf("after turning ACME on the gateway served %q (err %v)", cn, err)
	}

	cfg, err := f.base.GetConfigForClient(&tls.ClientHelloInfo{ServerName: host, SupportedProtos: []string{acme.ALPNProto}})
	if err != nil || cfg == nil || !slices.Contains(cfg.NextProtos, acme.ALPNProto) {
		t.Fatalf("after turning ACME on, a TLS-ALPN-01 validation handshake is offered %v (err %v); "+
			"without %s the CA cannot validate this gateway", nextProtos(cfg), err, acme.ALPNProto)
	}

	// A domain added with the switch: the host policy has to authorise it, so
	// issuance goes on to the CA -- which here is a closed port.
	_, err = f.s.TLSManager.GetCertificate(ecdsaHello(added))
	if err == nil || strings.Contains(err.Error(), "not authorized for ACME") {
		t.Fatalf("a domain added at runtime was refused by the host policy: %v", err)
	}
}

// A route that names its own certificates is served them. The base config's
// ACME hook was cloned into every route's config and, for any host ACME covers,
// answered first -- the route's certificate was never presented.
func TestARoutesOwnCertificateWinsOverGlobalACME(t *testing.T) {
	const host = "route-cert.example.test"
	certFile, keyFile := createTempCertKey(t, host)
	f := newACMEFixture(t, &gateonv1.TlsConfig{
		Enabled: true, Domains: []string{host}, Acme: &gateonv1.AcmeConfig{Enabled: true},
		Certificates: []*gateonv1.Certificate{{Id: "route-cert", Name: "route", CertFile: certFile, KeyFile: keyFile}},
	}, acmeCacheWithCert(t, host))
	if err := f.routes.Update(context.Background(), &gateonv1.Route{
		Id: "r-cert", ServiceId: "svc", Rule: "Host(`" + host + "`)",
		Tls: &gateonv1.RouteTLSConfig{CertificateIds: []string{"route-cert"}},
	}); err != nil {
		t.Fatalf("route: %v", err)
	}
	if cn, err := servedCN(f.base, host); err != nil || cn == acmeIssuedCN {
		t.Fatalf("a route with its own certificate was served %q (err %v)", cn, err)
	}
}

type acmeFixture struct {
	s       *Server
	base    *tls.Config
	globals *config.GlobalRegistry
	routes  *config.RouteRegistry
}

// newACMEFixture builds the TLS side of a server the way Run does -- the
// manager, its base config and SNI selection -- over tlsCfg, with cache as the
// ACME certificate cache.
func newACMEFixture(t *testing.T, tlsCfg *gateonv1.TlsConfig, cache autocert.Cache) *acmeFixture {
	t.Helper()
	resetTLSCaches(t)
	dir := t.TempDir()
	f := &acmeFixture{
		globals: config.NewGlobalRegistry(filepath.Join(dir, "global.json")),
		routes:  config.NewRouteRegistry(filepath.Join(dir, "routes.json")),
	}
	if err := f.globals.Update(context.Background(), &gateonv1.GlobalConfig{Tls: tlsCfg}); err != nil {
		t.Fatalf("globals: %v", err)
	}
	f.s = &Server{GlobalStore: f.globals, RouteStore: f.routes}
	m := CreateTLSManager(f.s)
	m.SetCache(cache)
	f.s.TLSManager = m
	base, err := m.GetTLSConfig()
	if err != nil || base == nil {
		t.Fatalf("GetTLSConfig: %v", err)
	}
	f.base = base
	SetupSNI(base, m, SNIDeps{
		RouteStore: f.routes, GlobalStore: f.globals,
		TLSOptStore: config.NewTLSOptionRegistry(filepath.Join(dir, "tls_options.json")),
	})
	return f
}

// save stores tlsCfg and invalidates TLS state, as saving settings does.
func (f *acmeFixture) save(t *testing.T, tlsCfg *gateonv1.TlsConfig) {
	t.Helper()
	if err := f.globals.Update(context.Background(), &gateonv1.GlobalConfig{Tls: tlsCfg}); err != nil {
		t.Fatalf("globals: %v", err)
	}
	(&serverProxyInvalidator{server: f.s}).InvalidateTLS()
}

// servedCN completes a handshake against base for host and returns the common
// name of the certificate the gateway presented.
//
// The raw pipe is closed rather than either TLS connection: net.Pipe does not
// buffer, and two close_notify alerts written at once wait for each other.
func servedCN(base *tls.Config, host string) (string, error) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	_ = clientConn.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)
	serverErr := make(chan error, 1)
	go func() { serverErr <- tls.Server(serverConn, base).Handshake() }()
	// #nosec G402 -- the test inspects which certificate is presented, not whether it is trusted.
	cli := tls.Client(clientConn, &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := cli.Handshake(); err != nil {
		_ = clientConn.Close()
		return "", fmt.Errorf("%w (server: %w)", err, <-serverErr)
	}
	return cli.ConnectionState().PeerCertificates[0].Subject.CommonName, nil
}

func nextProtos(cfg *tls.Config) []string {
	if cfg == nil {
		return nil
	}
	return cfg.NextProtos
}

func ecdsaHello(host string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:        host,
		CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedVersions: []uint16{tls.VersionTLS12},
	}
}

// acmeCacheWithCert returns an autocert cache holding a certificate for host,
// stored the way autocert stores one it obtained, so GetCertificate answers
// from it without asking a CA.
func acmeCacheWithCert(t *testing.T, host string) autocert.Cache {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: acmeIssuedCN},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	_ = pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cache := autocert.DirCache(t.TempDir())
	if err := cache.Put(context.Background(), host, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	return cache
}

// With ACME on and certificates configured as well, a host ACME does not
// cover is served a configured certificate. ACME answered first for every
// host and its refusal ended the handshake, so the certificates were
// unreachable by any client that sent SNI.
func TestACMEFallsThroughToConfiguredCertificatesForOtherHosts(t *testing.T) {
	const acmeHost, otherHost = "covered.example.test", "not-covered.example.test"
	certFile, keyFile := createTempCertKey(t, otherHost)
	f := newACMEFixture(t, &gateonv1.TlsConfig{
		Enabled: true, Domains: []string{acmeHost}, Acme: &gateonv1.AcmeConfig{Enabled: true},
		Certificates: []*gateonv1.Certificate{{Id: "manual", Name: "manual", CertFile: certFile, KeyFile: keyFile}},
	}, acmeCacheWithCert(t, acmeHost))

	if cn, err := servedCN(f.base, acmeHost); err != nil || cn != acmeIssuedCN {
		t.Fatalf("control: the host ACME covers was served %q (err %v)", cn, err)
	}
	if cn, err := servedCN(f.base, otherHost); err != nil || cn != otherHost {
		t.Fatalf("a host ACME does not cover was served %q (err %v), not the configured certificate", cn, err)
	}
}

// Every per-handshake config is cloned from the base config, and the base
// was built once at startup, so the global TLS settings saved from the
// dashboard -- the minimum version, the cipher suites, the client-certificate
// mode -- applied to nothing until a restart. Raised to TLS 1.3, the floor
// still let a TLS 1.2 client in.
func TestGlobalTLSSettingsTakeEffectWithoutARestart(t *testing.T) {
	const host = "floor.example.test"
	certFile, keyFile := createTempCertKey(t, host)
	cfg := func(minVersion string) *gateonv1.TlsConfig {
		return &gateonv1.TlsConfig{Enabled: true, MinTlsVersion: minVersion,
			Certificates: []*gateonv1.Certificate{{Id: "c", Name: "c", CertFile: certFile, KeyFile: keyFile}}}
	}
	f := newACMEFixture(t, cfg("TLS1.2"), autocert.DirCache(t.TempDir()))
	if err := handshakeAtMost(f.base, host, tls.VersionTLS12); err != nil {
		t.Fatalf("control: a TLS 1.2 client was refused with the floor at 1.2: %v", err)
	}

	f.save(t, cfg("TLS1.3"))
	if err := handshakeAtMost(f.base, host, tls.VersionTLS12); err == nil {
		t.Fatal("after raising the floor to TLS 1.3 a TLS 1.2 client still completed a handshake")
	}
	if err := handshakeAtMost(f.base, host, tls.VersionTLS13); err != nil {
		t.Fatalf("after raising the floor a TLS 1.3 client was refused: %v", err)
	}
}

// handshakeAtMost completes a handshake against base for host from a client
// that speaks at most version.
func handshakeAtMost(base *tls.Config, host string, version uint16) error {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	_ = clientConn.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)
	go func() { _ = tls.Server(serverConn, base).Handshake() }()
	// #nosec G402 -- the test is about the version floor, not the certificate.
	return tls.Client(clientConn, &tls.Config{ServerName: host, InsecureSkipVerify: true,
		MinVersion: tls.VersionTLS12, MaxVersion: version}).Handshake()
}
