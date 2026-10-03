// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The end-to-end behaviour -- a real TLS server, client certificates, a cookie
// jar -- is pinned through the factory in internal/middleware
// (tls_binding_truth_test.go). These cover the pieces a request does not reach
// on its own.

var testSecret = []byte(strings.Repeat("s", 32))

func withPeer(r *http.Request, der []byte) *http.Request {
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true,
		PeerCertificates: []*x509.Certificate{{Raw: der}}}
	return r
}

func bindingHandler(reached *bool) http.Handler {
	return TLSBinding(TLSBindingConfig{CookieName: "session", Secret: testSecret})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			*reached = true
			w.WriteHeader(http.StatusOK)
		}))
}

// TestTlsBindingRefusesASessionWithNoBinding: omitting the binding cookie must
// not be a way around it, and nothing is minted for a session the gateway did
// not see issued.
func TestTlsBindingRefusesASessionWithNoBinding(t *testing.T) {
	var reached bool
	r := withPeer(httptest.NewRequest(http.MethodGet, "https://x/", nil), []byte("cert-A"))
	r.AddCookie(&http.Cookie{Name: "session", Value: "stolen-session-value"})
	rec := httptest.NewRecorder()
	bindingHandler(&reached).ServeHTTP(rec, r)

	if reached || rec.Code != http.StatusForbidden {
		t.Errorf("a session with no binding cookie: reached=%v status=%d, want refused with 403", reached, rec.Code)
	}
	if sc := rec.Result().Cookies(); len(sc) > 0 {
		t.Errorf("a binding cookie was issued to an unbound session: %v", sc)
	}
}

// TestTlsBindingBindingDependsOnCertificateSessionAndSecret: each input
// changes the binding, so none can be swapped under a stolen one.
func TestTlsBindingBindingDependsOnCertificateSessionAndSecret(t *testing.T) {
	b := tlsBinder{cookie: "session", binding: "session_binding", secret: testSecret}
	base := b.mac([]byte("cert-A"), "sess-1")
	other := tlsBinder{cookie: "session", binding: "session_binding", secret: []byte(strings.Repeat("t", 32))}
	for name, got := range map[string]string{
		"another certificate": b.mac([]byte("cert-B"), "sess-1"),
		"another session":     b.mac([]byte("cert-A"), "sess-2"),
		"another secret":      other.mac([]byte("cert-A"), "sess-1"),
	} {
		if got == base {
			t.Errorf("%s produced the same binding", name)
		}
	}
}

// TestNewTLSBindingDefaultsTheCookieName: an empty cookie_name binds "session".
func TestNewTLSBindingDefaultsTheCookieName(t *testing.T) {
	mw, err := NewTLSBinding(map[string]string{"secret": string(testSecret)})
	if err != nil {
		t.Fatal(err)
	}
	var reached bool
	r := withPeer(httptest.NewRequest(http.MethodGet, "https://x/", nil), []byte("cert-A"))
	r.AddCookie(&http.Cookie{Name: "session", Value: "v"})
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).ServeHTTP(httptest.NewRecorder(), r)
	if reached {
		t.Fatal("an unbound \"session\" cookie passed a tls_binding with no cookie_name")
	}
}
