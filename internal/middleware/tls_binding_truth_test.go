// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// tls_binding (ADR 0046) refused every TLS session that carried a "session"
// cookie -- nothing ever issued the binding it checked -- and did nothing over
// plain HTTP. It now binds the session cookie the backend issues to the client
// certificate of the connection that received it, and refuses that cookie from
// any other certificate, from none, and over plaintext.

const tlsBindingSecret = "tls-binding-test-secret-0123456789abcdef"

// sessionBackend issues a session cookie on /login, expires it on /logout, and
// answers 200 "app" anywhere else.
func sessionBackend() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "s3cr3t-session", Path: "/", HttpOnly: true, Secure: true})
		case "/logout":
			// Emptied rather than given a past expiry, as some frameworks
			// sign out; the binding must end either way.
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/"})
		}
		_, _ = io.WriteString(w, "app")
	})
}

func buildTLSBinding(t *testing.T, cfg map[string]string) Middleware {
	t.Helper()
	mw, err := NewFactory(nil, nil, nil, nil, t.TempDir()).
		Create(&gateonv1.Middleware{Id: "tlsb", Type: "tls_binding", Config: cfg}, "route-under-test")
	if err != nil {
		t.Fatalf("build tls_binding: %v", err)
	}
	return mw
}

// bindingClient is a client with its own cookie jar presenting cert (none when
// nil) to srv.
func bindingClient(t *testing.T, srv *httptest.Server, cert *tls.Certificate) *http.Client {
	t.Helper()
	c := mtlsClient(t, srv, cert)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Jar = jar
	return c
}

func getStatus(t *testing.T, c *http.Client, target string) int {
	t.Helper()
	resp, err := c.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func tlsBindingServer(t *testing.T) *httptest.Server {
	t.Helper()
	return mtlsServer(t, buildTLSBinding(t, map[string]string{"secret": tlsBindingSecret})(sessionBackend()))
}

// TestTLSBindingBindsTheIssuedSessionToTheClientCertificate logs in with a
// client certificate and uses the session, across a new TLS connection.
func TestTLSBindingBindsTheIssuedSessionToTheClientCertificate(t *testing.T) {
	srv := tlsBindingServer(t)
	cert := newClientCert(t, clientCertSpec{commonName: "alice"})
	alice := bindingClient(t, srv, &cert)

	if code := getStatus(t, alice, srv.URL+"/login"); code != http.StatusOK {
		t.Fatalf("login got %d", code)
	}
	u, _ := url.Parse(srv.URL)
	if !hasCookie(alice.Jar.Cookies(u), "session_binding") {
		t.Fatalf("no session_binding cookie was issued with the session: cookies %v", alice.Jar.Cookies(u))
	}
	if code := getStatus(t, alice, srv.URL+"/app"); code != http.StatusOK {
		t.Fatalf("the session's own client got %d on its next request, want 200", code)
	}
	// A fresh TLS connection: the binding is to the certificate, not the
	// connection, so it survives the reconnect every browser makes.
	alice.Transport.(*http.Transport).CloseIdleConnections()
	if code := getStatus(t, alice, srv.URL+"/app"); code != http.StatusOK {
		t.Fatalf("the session got %d on a new TLS connection with the same certificate, want 200", code)
	}
}

// TestTLSBindingRefusesTheSessionFromAnotherCertificate replays alice's cookies
// -- session and binding both -- from mallory's certificate, and from none.
func TestTLSBindingRefusesTheSessionFromAnotherCertificate(t *testing.T) {
	srv := tlsBindingServer(t)
	aliceCert := newClientCert(t, clientCertSpec{commonName: "alice"})
	alice := bindingClient(t, srv, &aliceCert)
	getStatus(t, alice, srv.URL+"/login")
	u, _ := url.Parse(srv.URL)
	stolen := alice.Jar.Cookies(u)

	malloryCert := newClientCert(t, clientCertSpec{commonName: "mallory"})
	for name, c := range map[string]*http.Client{
		"another certificate": bindingClient(t, srv, &malloryCert),
		"no certificate":      bindingClient(t, srv, nil),
	} {
		c.Jar.SetCookies(u, stolen)
		if code := getStatus(t, c, srv.URL+"/app"); code != http.StatusForbidden {
			t.Errorf("alice's session and binding cookies from %s got %d, want 403", name, code)
		}
	}
}

// TestTLSBindingExpiresTheBindingWithTheSession: a logout that expires the
// session expires its binding too.
func TestTLSBindingExpiresTheBindingWithTheSession(t *testing.T) {
	srv := tlsBindingServer(t)
	cert := newClientCert(t, clientCertSpec{commonName: "alice"})
	alice := bindingClient(t, srv, &cert)
	getStatus(t, alice, srv.URL+"/login")
	getStatus(t, alice, srv.URL+"/logout")
	u, _ := url.Parse(srv.URL)
	if hasCookie(alice.Jar.Cookies(u), "session_binding") {
		t.Fatalf("the binding outlived the session it bound: %v", alice.Jar.Cookies(u))
	}
}

// TestTLSBindingRefusesASessionOverPlaintext: over HTTP there is no
// certificate to bind to, and a session cookie is refused rather than passed.
func TestTLSBindingRefusesASessionOverPlaintext(t *testing.T) {
	srv := httptest.NewServer(buildTLSBinding(t, map[string]string{"secret": tlsBindingSecret})(sessionBackend()))
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/app", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "s3cr3t-session"})
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a session cookie over plain HTTP got %d, want 403: tls_binding did nothing", resp.StatusCode)
	}
	resp, err = srv.Client().Get(srv.URL + "/app")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a request with no session over plain HTTP got %d, want 200", resp.StatusCode)
	}
}

// TestTLSBindingNeedsASecret: the binding is an HMAC every node must be able to
// check, so a config without a shared secret is refused.
func TestTLSBindingNeedsASecret(t *testing.T) {
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	for _, secret := range []string{"", "short"} {
		_, err := f.Create(&gateonv1.Middleware{Id: "tlsb", Type: "tls_binding", Config: map[string]string{"secret": secret}}, "r")
		if err == nil || !strings.Contains(err.Error(), "secret") {
			t.Errorf("tls_binding with secret %q: err = %v, want a refusal naming the secret", secret, err)
		}
	}
}

func hasCookie(cs []*http.Cookie, name string) bool {
	for _, c := range cs {
		if c.Name == name && c.Value != "" {
			return true
		}
	}
	return false
}
