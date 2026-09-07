// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// HMAC verifies webhook signatures and shipped with no tests at all.
//
// It is the kind of code where an absence is invisible: everything here either
// compares equal or it does not, and a mistake shows up as a webhook that "just
// stopped working" against a provider that says it is signing correctly.

func sign(secret, body string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(body))
	return hex.EncodeToString(m.Sum(nil))
}

// serveHMAC drives a signed request and returns the response plus what the
// backend saw, so a test can tell "denied" from "passed through with a body the
// backend cannot trust".
func serveHMAC(t *testing.T, cfg HMACConfig, method, body, sigHeader, sigValue string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	mw, err := HMAC(cfg)
	if err != nil {
		t.Fatalf("build HMAC: %v", err)
	}

	var seen string
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = string(b)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(method, "/webhook", strings.NewReader(body))
	if sigValue != "" {
		req.Header.Set(sigHeader, sigValue)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr, seen
}

// TestHMACRequiresASecret pins the one thing the constructor refuses.
func TestHMACRequiresASecret(t *testing.T) {
	if _, err := HMAC(HMACConfig{}); err == nil {
		t.Error("HMAC built without a secret; every signature would verify against " +
			"an empty key, which any caller can compute")
	}
}

// TestHMACVerifiesSignatures is the core contract.
func TestHMACVerifiesSignatures(t *testing.T) {
	const secret, body = "s3cr3t", `{"event":"push"}`
	cfg := HMACConfig{Secret: secret}

	t.Run("valid signature passes", func(t *testing.T) {
		rr, seen := serveHMAC(t, cfg, http.MethodPost, body,
			"X-Signature-256", "sha256="+sign(secret, body))
		if rr.Code != http.StatusOK {
			t.Fatalf("got %d, want 200", rr.Code)
		}
		if seen != body {
			t.Errorf("the backend read %q, want the original body — verification "+
				"consumes the body and must put it back", seen)
		}
	})

	t.Run("wrong secret is refused", func(t *testing.T) {
		rr, _ := serveHMAC(t, cfg, http.MethodPost, body,
			"X-Signature-256", "sha256="+sign("wrong-secret", body))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want 401", rr.Code)
		}
	})

	t.Run("tampered body is refused", func(t *testing.T) {
		rr, _ := serveHMAC(t, cfg, http.MethodPost, `{"event":"delete"}`,
			"X-Signature-256", "sha256="+sign(secret, body))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want 401 — the signature is for a different body", rr.Code)
		}
	})

	t.Run("missing signature is refused", func(t *testing.T) {
		rr, _ := serveHMAC(t, cfg, http.MethodPost, body, "X-Signature-256", "")
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want 401", rr.Code)
		}
	})

	t.Run("malformed signatures are refused", func(t *testing.T) {
		for _, sig := range []string{
			"sha256=not-hex",
			"sha256=" + strings.Repeat("ab", 16), // right alphabet, wrong length
			"sha256=",
			strings.Repeat("f", 64) + "extra",
		} {
			rr, _ := serveHMAC(t, cfg, http.MethodPost, body, "X-Signature-256", sig)
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("signature %q got %d, want 401", sig, rr.Code)
			}
		}
	})
}

// TestHMACPrefixHandling covers the provider-specific prefix.
func TestHMACPrefixHandling(t *testing.T) {
	const secret, body = "s3cr3t", "payload"

	t.Run("default prefix", func(t *testing.T) {
		rr, _ := serveHMAC(t, HMACConfig{Secret: secret}, http.MethodPost, body,
			"X-Signature-256", "sha256="+sign(secret, body))
		if rr.Code != http.StatusOK {
			t.Errorf("got %d, want 200", rr.Code)
		}
	})

	t.Run("bare hex with no prefix", func(t *testing.T) {
		// Providers differ; a bare signature must still verify.
		rr, _ := serveHMAC(t, HMACConfig{Secret: secret}, http.MethodPost, body,
			"X-Signature-256", sign(secret, body))
		if rr.Code != http.StatusOK {
			t.Errorf("got %d, want 200", rr.Code)
		}
	})

	t.Run("custom header and prefix", func(t *testing.T) {
		cfg := HMACConfig{Secret: secret, Header: "X-Hub-Signature-256", Prefix: "sha256="}
		rr, _ := serveHMAC(t, cfg, http.MethodPost, body,
			"X-Hub-Signature-256", "sha256="+sign(secret, body))
		if rr.Code != http.StatusOK {
			t.Errorf("got %d, want 200", rr.Code)
		}
	})

	t.Run("surrounding whitespace is tolerated", func(t *testing.T) {
		rr, _ := serveHMAC(t, HMACConfig{Secret: secret}, http.MethodPost, body,
			"X-Signature-256", "  sha256= "+sign(secret, body)+"  ")
		if rr.Code != http.StatusOK {
			t.Errorf("got %d, want 200", rr.Code)
		}
	})
}

// TestHMACMethodFilterSkipsRatherThanDenies records a sharp edge.
//
// Configuring Methods restricts *which methods are verified*, and everything
// else passes through unverified rather than being refused. That is the intent —
// a webhook endpoint that also serves GET should not 401 the GET — but it means
// an endpoint configured for POST only does not verify the same payload sent as
// PUT. Written down because the config key reads like a filter on what is
// allowed, and it is a filter on what is checked.
func TestHMACMethodFilterSkipsRatherThanDenies(t *testing.T) {
	cfg := HMACConfig{Secret: "s3cr3t", Methods: []string{"POST"}}

	rr, _ := serveHMAC(t, cfg, http.MethodPost, "body", "X-Signature-256", "")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("an unsigned POST got %d, want 401", rr.Code)
	}

	rr, _ = serveHMAC(t, cfg, http.MethodPut, "body", "X-Signature-256", "")
	if rr.Code != http.StatusOK {
		t.Errorf("an unsigned PUT got %d; the method filter selects what is verified, "+
			"and anything outside it is forwarded unverified", rr.Code)
	}
}

// TestHMACOversizeBodyIsNotReportedAsABadSignature is the diagnosability case.
//
// The body is read under a limit and the signature computed over what was read,
// so a payload larger than the limit is signed in part and compared in full. It
// cannot match, so the request is correctly refused — but it is refused as
// "Invalid signature", which sends an operator to check a secret that is fine
// while the provider insists it is signing correctly.
//
// The refusal is right; the reason given for it is not. A body that exceeded the
// limit was not unsigned, it was too large, and only one of those two is
// something the sender can act on.
func TestHMACOversizeBodyIsNotReportedAsABadSignature(t *testing.T) {
	const secret = "s3cr3t"
	body := strings.Repeat("A", 2048)
	cfg := HMACConfig{Secret: secret, BodyLimit: 1024}

	rr, _ := serveHMAC(t, cfg, http.MethodPost, body,
		"X-Signature-256", "sha256="+sign(secret, body))

	if rr.Code == http.StatusOK {
		t.Fatal("a body past the limit was accepted; the signature covers only the " +
			"bytes that were read, so accepting it would forward a body nobody " +
			"verified")
	}
	if got := strings.TrimSpace(rr.Body.String()); strings.Contains(got, "Invalid signature") {
		t.Errorf("an oversize body was refused as %q.\n"+
			"It is refused correctly, but the reason is wrong and unactionable: the "+
			"sender signed the whole payload, the gateway hashed the first %d bytes "+
			"of it, and the operator is told their signature is bad. Say the body "+
			"was too large.", got, cfg.BodyLimit)
	}
}

// TestHMACRestoresTheBodyForTheBackend pins the replay.
//
// Verification has to consume the body to hash it. If it is not put back, the
// backend receives an empty request and the failure looks like a webhook that
// authenticates and then does nothing.
func TestHMACRestoresTheBodyForTheBackend(t *testing.T) {
	const secret = "s3cr3t"
	body := strings.Repeat("payload-", 500)

	_, seen := serveHMAC(t, HMACConfig{Secret: secret}, http.MethodPost, body,
		"X-Signature-256", "sha256="+sign(secret, body))

	if seen != body {
		t.Errorf("the backend read %d bytes, want %d — the body must survive "+
			"verification intact, including across multiple Read calls",
			len(seen), len(body))
	}
}
