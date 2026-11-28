// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"crypto/sha512"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

const chromeUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

// highEntropyValue is 96 bytes of hash output in base64: as close to random
// as a header value gets, and long enough to be scored.
func highEntropyValue() string {
	a, b := sha512.Sum512([]byte("a")), sha512.Sum512([]byte("b"))
	return base64.StdEncoding.EncodeToString(append(a[:], b[:32]...))
}

// TestEveryRefusalTellsTheClientTheSameThing is ADR 0106. Each refusal used to
// name the check that fired -- "High Entropy Detected", "Suspicious Client",
// "Malformed Security Token", "Reputation Block", "response blocked" -- which
// tells a client that adapts its payload from each answer exactly what to
// change. Whatever refuses, the body is kind.RefusalBody; only the status,
// which carries HTTP semantics, may differ.
func TestEveryRefusalTellsTheClientTheSameThing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cfg    WAFConfig
		req    func() *http.Request
		status int
	}{
		{
			name: "a rule's decision",
			cfg:  WAFConfig{ParanoiaLevel: 1},
			req: func() *http.Request {
				return httptest.NewRequest(http.MethodGet,
					"/search?q="+url.QueryEscape("<script>alert(1)</script>"), nil)
			},
			status: http.StatusForbidden,
		},
		{
			name: "header entropy",
			cfg:  WAFConfig{ParanoiaLevel: 1, EntropyThreshold: 4},
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("X-Blob", highEntropyValue())
				return r
			},
			status: http.StatusForbidden,
		},
		{
			name: "a method outside the allowlist",
			cfg:  WAFConfig{ParanoiaLevel: 1, AllowedMethods: map[string]bool{http.MethodGet: true}},
			req: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/", strings.NewReader("a=1"))
			},
			status: http.StatusMethodNotAllowed,
		},
		{
			name: "a browser that does not behave like one",
			cfg:  WAFConfig{ParanoiaLevel: 1, EnableFingerprintValidation: true},
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/2.0", 2, 0
				r.Header.Set("User-Agent", chromeUA)
				r.Header.Del("Accept-Encoding")
				return r
			},
			status: http.StatusForbidden,
		},
		{
			name: "a token that claims to be a JWT and is not",
			cfg:  WAFConfig{ParanoiaLevel: 1},
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Authorization", "Bearer eyJ"+strings.Repeat("A", 40)+".!!")
				return r
			},
			status: http.StatusForbidden,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.RouteID = t.Name()
			mw, err := WAF(tc.cfg)
			if err != nil {
				t.Fatalf("create WAF: %v", err)
			}
			rr := httptest.NewRecorder()
			mw(okOrigin()).ServeHTTP(rr, tc.req())
			assertUniformRefusal(t, rr, tc.status)
		})
	}
}

// TestARefusedResponseAndAReputationBlockSayTheSameThing covers the two
// refusals that are not the request phase's: a response the WAF replaced, and
// the reputation blocker in front of it refusing a client it holds evidence
// against.
func TestARefusedResponseAndAReputationBlockSayTheSameThing(t *testing.T) {
	t.Run("a refused response", func(t *testing.T) {
		const reader = "203.0.113.70"
		h, _ := innocentRoute(t, map[string]string{"dlp": "true", "dlp_action": "block"}, innocentPage)
		t.Cleanup(func() { telemetry.ResetReputation(repid.For(stockBuild, reader)) })
		rr := visit(t, h, reader, httptest.NewRequest(http.MethodGet, "/orders/1", nil))
		assertUniformRefusal(t, rr, http.StatusForbidden)
	})
	t.Run("a reputation block", func(t *testing.T) {
		const attacker = "198.18.6.6"
		h, threats := innocentRoute(t, map[string]string{"audit_only": "false"}, plainPage)
		t.Cleanup(func() { telemetry.ResetReputation(repid.For(stockBuild, attacker)) })
		for range 2 {
			visit(t, h, attacker, xssProbe())
		}
		_ = recorded(threats)
		rr := visit(t, h, attacker, httptest.NewRequest(http.MethodGet, "/home", nil))
		if !hasThreat(recorded(threats), "reputation_block") {
			t.Fatal("the reputation blocker did not refuse, so this proves nothing about its body")
		}
		assertUniformRefusal(t, rr, http.StatusForbidden)
	})
}

func assertUniformRefusal(t *testing.T, rr *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rr.Code != status {
		t.Fatalf("got %d (%q), want a %d refusal", rr.Code, rr.Body.String(), status)
	}
	if got := rr.Body.String(); got != kind.RefusalBody {
		t.Errorf("the refusal's body is %q, want %q: it tells the client which check fired", got, kind.RefusalBody)
	}
}
