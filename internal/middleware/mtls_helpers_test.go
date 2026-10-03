// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// clientCertSpec is what a test client certificate says about its holder.
type clientCertSpec struct {
	commonName string
	uris       []string
	dnsNames   []string
}

// newClientCert issues a self-signed client certificate. The servers below
// ask for any client certificate and do not verify it: what is under test is
// what the middleware does with the one presented, not the chain.
func newClientCert(t *testing.T, spec clientCertSpec) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: spec.commonName, Organization: []string{"rv"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     spec.dnsNames,
	}
	for _, raw := range spec.uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// mtlsServer serves h over TLS, asking every client for a certificate.
func mtlsServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// mtlsClient is srv's client presenting cert (none when cert is nil). Each
// client has its own transport, so its connections are its own.
func mtlsClient(t *testing.T, srv *httptest.Server, cert *tls.Certificate) *http.Client {
	t.Helper()
	base, ok := srv.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("httptest client transport is not an *http.Transport")
	}
	tr := base.Clone()
	if cert != nil {
		tr.TLSClientConfig.Certificates = []tls.Certificate{*cert}
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}
