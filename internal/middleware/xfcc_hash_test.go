// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func xfccTestClientCert(t *testing.T) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

// Envoy defines the XFCC Hash element as the SHA-256 of the client's DER
// certificate, and that is what upstreams pin against. Forwarding any other
// value under that name makes every such pin fail to match, silently.
func TestXFCC_HashIsSHA256OfClientCertDER(t *testing.T) {
	cert := xfccTestClientCert(t)

	var got string
	h := XFCC(XFCCConfig{ForwardHash: true})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Forwarded-Client-Cert")
	}))
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	h.ServeHTTP(httptest.NewRecorder(), req)

	sum := sha256.Sum256(cert.Raw)
	if want := "Hash=" + hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("XFCC = %q, want %q (SHA-256 of the DER certificate)", got, want)
	}
}
