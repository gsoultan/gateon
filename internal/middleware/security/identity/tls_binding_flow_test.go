// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func selfSignedClientCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// bindingFlowServer serves backend behind TLSBinding over TLS, asking every
// client for a certificate.
func bindingFlowServer(t *testing.T, backend http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(TLSBinding(TLSBindingConfig{CookieName: "sid", Secret: testSecret})(backend))
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func certClient(t *testing.T, srv *httptest.Server, cert tls.Certificate) *http.Client {
	t.Helper()
	tr, ok := srv.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("not an *http.Transport")
	}
	tr = tr.Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

func setCookies(t *testing.T, c *http.Client, url string) []*http.Cookie {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.Cookies()
}

func cookieNamed(cs []*http.Cookie, name string) *http.Cookie {
	for _, c := range cs {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestTLSBindingIssuesWithAFlushedOrUnwrittenResponse: a backend that flushes
// before writing (a streaming proxy does), or writes nothing at all, still
// gets the binding issued with the headers that carry the session.
func TestTLSBindingIssuesWithAFlushedOrUnwrittenResponse(t *testing.T) {
	srv := bindingFlowServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "v1", Path: "/", SameSite: http.SameSiteNoneMode, Secure: true})
		if r.URL.Path == "/flush" {
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Errorf("flush: %v", err)
			}
			_, _ = io.WriteString(w, "streamed")
		}
	}))
	c := certClient(t, srv, selfSignedClientCert(t, "alice"))
	for _, path := range []string{"/flush", "/silent"} {
		b := cookieNamed(setCookies(t, c, srv.URL+path), "sid_binding")
		if b == nil || b.Value == "" {
			t.Fatalf("%s: no binding issued", path)
		}
		if !b.HttpOnly || !b.Secure || b.SameSite != http.SameSiteNoneMode {
			t.Errorf("%s: binding cookie %+v; want HttpOnly, Secure and the session's SameSite=None", path, b)
		}
	}
}

// TestTLSBindingExpiresTheBindingWhenTheSessionIsExpired covers a logout by
// Max-Age, the other way a backend ends a session.
func TestTLSBindingExpiresTheBindingWhenTheSessionIsExpired(t *testing.T) {
	srv := bindingFlowServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "v1", Path: "/", MaxAge: -1})
	}))
	b := cookieNamed(setCookies(t, certClient(t, srv, selfSignedClientCert(t, "alice")), srv.URL+"/logout"), "sid_binding")
	if b == nil || b.MaxAge >= 0 || b.Value != "" {
		t.Fatalf("binding %+v; want an expired, empty one", b)
	}
}

// TestTLSBindingHandsOverAHijackedConnection: a WebSocket upgrade needs the
// connection, and the wrapper must give it.
func TestTLSBindingHandsOverAHijackedConnection(t *testing.T) {
	srv := bindingFlowServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack through the binding writer: %v", err)
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: Upgrade\r\n\r\nhello")
		_ = rw.Flush()
	}))
	cert := selfSignedClientCert(t, "alice")
	cfg := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	cfg.Certificates = []tls.Certificate{cert}
	cfg.NextProtos = []string{"http/1.1"}
	conn, err := tls.Dial("tcp", strings.TrimPrefix(srv.URL, "https://"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: x\r\nConnection: Upgrade\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d, want 101", resp.StatusCode)
	}
}

// TestBindingWriterWithoutHijackerSaysSo: a writer that cannot be hijacked is
// reported as such, not as a nil connection.
func TestBindingWriterWithoutHijackerSaysSo(t *testing.T) {
	w := &bindingWriter{ResponseWriter: httptest.NewRecorder()}
	if _, _, err := w.Hijack(); !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("err = %v, want http.ErrNotSupported", err)
	}
}
