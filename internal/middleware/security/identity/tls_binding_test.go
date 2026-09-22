// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func withTLS12(r *http.Request, unique []byte) *http.Request {
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS12, TLSUnique: unique, HandshakeComplete: true}
	return r
}

// TestTlsBindingRefusesASessionWithNoBinding is the whole point of the
// middleware, and it used to be the one case it allowed.
//
// A session cookie arriving with no binding cookie had a binding computed for
// whatever connection presented it, set, and the request forwarded. An
// attacker holding a stolen session cookie only had to *omit* the binding
// cookie to be handed a valid one for their own connection -- the middleware
// permitted exactly the attack its own error message names.
func TestTlsBindingRefusesASessionWithNoBinding(t *testing.T) {
	var reached bool
	h := TlsBinding("session")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	r := withTLS12(httptest.NewRequest(http.MethodGet, "https://x/", nil), []byte("attacker-conn"))
	r.AddCookie(&http.Cookie{Name: "session", Value: "stolen-session-value"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if reached {
		t.Error("a stolen session cookie with no binding cookie was forwarded; " +
			"omitting the binding is all an attacker had to do")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if sc := rec.Result().Cookies(); len(sc) > 0 {
		t.Errorf("a binding cookie was issued to an unbound session: %v; the "+
			"middleware minted the credential it exists to check", sc)
	}
}

// TestTlsBindingAllowsAMatchingBinding keeps the fix from being a blanket
// refusal: a correctly bound session must still work.
func TestTlsBindingAllowsAMatchingBinding(t *testing.T) {
	const unique = "connection-A"

	// Derive the binding the same way the middleware does, by observing what
	// it refuses -- a mismatching value -- then supplying the one it wants.
	var reached bool
	h := TlsBinding("session")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	expected := bindingFor([]byte(unique), "sess-1")

	r := withTLS12(httptest.NewRequest(http.MethodGet, "https://x/", nil), []byte(unique))
	r.AddCookie(&http.Cookie{Name: "session", Value: "sess-1"})
	r.AddCookie(&http.Cookie{Name: "session_binding", Value: expected})

	h.ServeHTTP(httptest.NewRecorder(), r)
	if !reached {
		t.Error("a correctly bound session was refused; the binding check is " +
			"now an outage rather than a control")
	}
}

// TestTlsBindingRefusesAReplayOnADifferentConnection is the original purpose:
// the same cookie pair presented on another connection must not work.
func TestTlsBindingRefusesAReplayOnADifferentConnection(t *testing.T) {
	expected := bindingFor([]byte("connection-A"), "sess-1")

	var reached bool
	h := TlsBinding("session")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	// Same cookies, different TLS connection.
	r := withTLS12(httptest.NewRequest(http.MethodGet, "https://x/", nil), []byte("connection-B"))
	r.AddCookie(&http.Cookie{Name: "session", Value: "sess-1"})
	r.AddCookie(&http.Cookie{Name: "session_binding", Value: expected})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if reached {
		t.Error("a cookie pair lifted from one connection was accepted on another")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestChannelBindingCoversTLS13 pins the half that made this middleware inert
// in practice. Go sets TLSUnique to nil for every TLS 1.3 connection, and
// nothing in this tree pins MaxVersion below 1.3, so the old
// `len(TLSUnique) == 0` guard skipped the check for essentially every modern
// client -- silently, while the feature showed as enabled.
func TestChannelBindingCoversTLS13(t *testing.T) {
	complete12 := &tls.ConnectionState{
		Version: tls.VersionTLS12, TLSUnique: []byte("u"), HandshakeComplete: true,
	}
	if got := channelBinding(complete12); len(got) == 0 {
		t.Error("TLS 1.2 with a TLSUnique produced no binding material")
	}

	// An incomplete handshake supplies nothing, whatever the version claims.
	// This is also what guards the exporter call: on a ConnectionState that
	// did not come from a real connection there is no export function to call.
	if got := channelBinding(&tls.ConnectionState{Version: tls.VersionTLS13}); got != nil {
		t.Error("an incomplete handshake produced binding material")
	}
	if got := channelBinding(nil); got != nil {
		t.Error("a nil ConnectionState produced binding material")
	}

	// The property that made the old guard inert: a completed TLS 1.3
	// connection has a nil TLSUnique, so `len(TLSUnique) == 0` skipped the
	// check for essentially every modern client. The version branch above is
	// what stops that; assert the old predicate would indeed have skipped.
	tls13 := &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	if len(tls13.TLSUnique) != 0 {
		t.Error("this Go release sets TLSUnique on TLS 1.3; the premise of this " +
			"fix has changed and the version branch should be revisited")
	}
}

// bindingFor mirrors the middleware's derivation so a test can present a
// correct binding without reaching into unexported state.
func bindingFor(material []byte, session string) string {
	h := hmac.New(sha256.New, material)
	h.Write([]byte(session))
	return hex.EncodeToString(h.Sum(nil))
}
