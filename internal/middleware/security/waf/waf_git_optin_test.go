// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// injectionBody is a JSON body any backend that parses without checking the
// Content-Type would act on.
const injectionBody = `{"user":"admin' OR '1'='1' -- ","cmd":"; cat /etc/passwd"}`

// TestWAF_GitContentTypeDoesNotSkipBodyInspection: the exemption for git's
// packfiles used to apply to anything that named git in its Content-Type or
// path, gated on a reputation score that every client the gateway has not seen
// carries at the top of the scale. A body of any size, with any payload, then
// reached the backend uninspected. The body exemption now belongs to a route or
// deployment that says it hosts git.
func TestWAF_GitContentTypeDoesNotSkipBodyInspection(t *testing.T) {
	mw, err := WAF(WAFConfig{ParanoiaLevel: 1})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	handler := mw(okOrigin())

	for _, tc := range []struct{ name, path, ct string }{
		{"upload-pack content type", "/api/login", "application/x-git-upload-pack-request"},
		{"receive-pack content type", "/api/login", "application/x-git-receive-pack-request"},
		{"upload-pack path suffix", "/api/git-upload-pack", "application/json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(injectionBody))
			req.Header.Set("Content-Type", tc.ct)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("injection in the body, claiming git via %s: got %d, want 403 — the body was skipped on a value the client chose", tc.name, rr.Code)
			}
		})
	}
}

// TestWAF_GitSmartHTTPOptIn: the operator's switch reaches the engine from the
// route key and from the deployment environment, an explicit route value beats
// the environment in both directions, and unset is off.
func TestWAF_GitSmartHTTPOptIn(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		key  string
		want bool
	}{
		{"unset is off", "", "", false},
		{"route key on", "", "true", true},
		{"route key 1", "", "1", true},
		{"route key off", "", "false", false},
		{"environment on", "true", "", true},
		{"route off beats environment on", "true", "false", false},
		{"route on beats environment off", "false", "true", true},
		{"junk is off", "", "yes please", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(gitSmartHTTPEnv, tc.env)
			cfg := map[string]string{}
			if tc.key != "" {
				cfg["git_smart_http"] = tc.key
			}
			if got := parseWAFConfig(cfg).AllowGitSmartHTTP; got != tc.want {
				t.Fatalf("AllowGitSmartHTTP = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWAF_GitSmartHTTPOptInIsPartOfTheCacheKey: two configs that differ only in
// the switch describe different behaviour and must not share a cached engine.
func TestWAF_GitSmartHTTPOptInIsPartOfTheCacheKey(t *testing.T) {
	off := WAFConfig{ParanoiaLevel: 1}
	on := WAFConfig{ParanoiaLevel: 1, AllowGitSmartHTTP: true}
	if off.Fingerprint() == on.Fingerprint() {
		t.Fatal("configs differing only in AllowGitSmartHTTP share a fingerprint")
	}
}
