// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tls

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
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// cachedACMECert stores a certificate for host in an autocert cache the way
// autocert stores one it obtained: the EC key, then the chain. With it cached,
// GetCertificate answers without asking a CA.
func cachedACMECert(t *testing.T, host string) autocert.Cache {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
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

// TestRouteACMEWorksWithoutTheGlobalSwitch: a route can take its certificate
// from ACME (tls.acme_enabled on the route) while ACME is off gateway-wide --
// the host policy already authorises such routes' hosts. The autocert manager
// was only ever built when the global switch was on, so every handshake for
// the route's host failed with "ACME not initialized", and the host was
// unreachable over TLS.
func TestRouteACMEWorksWithoutTheGlobalSwitch(t *testing.T) {
	const host = "route-acme.example"
	m := NewManager(Config{Enabled: true})
	m.SetCache(cachedACMECert(t, host))
	m.SetHostPolicy(func(_ context.Context, h string) error { return nil })

	hello := &tls.ClientHelloInfo{
		ServerName:        host,
		CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedVersions: []uint16{tls.VersionTLS12},
	}
	// Several handshakes at once: the first builds the manager, and -race
	// checks that none of them sees it half-built.
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() {
			cert, err := m.GetCertificate(hello)
			if err == nil && (cert == nil || cert.Leaf == nil || cert.Leaf.Subject.CommonName != host) {
				err = errWrongCert
			}
			errs[i] = err
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("route-level ACME with the global switch off: %v", err)
		}
	}

	// And the HTTP-01 handler answers for it too, once the manager exists.
	h := m.HTTPChallengeHandler(http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://"+host+"/.well-known/acme-challenge/unknown-token", nil))
	if rec.Code == http.StatusNotFound && rec.Body.String() == "404 page not found\n" {
		t.Error("the HTTP-01 path went to the fallback handler instead of autocert")
	}
}

type wrongCertError struct{}

func (wrongCertError) Error() string { return "got a certificate for another host" }

var errWrongCert = wrongCertError{}
