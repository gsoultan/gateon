// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBotManagement_Challenge(t *testing.T) {
	secret := "test-secret"
	cfg := BotManagementConfig{
		Enabled:                 true,
		EnableJSChallenge:       true,
		ChallengeTimeoutSeconds: 3600,
		SecretKey:               secret,
	}
	mw := BotManagement(cfg)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 1. New request should get challenge
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for initial request, got %d. Body: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Security Challenge") {
		t.Errorf("expected challenge in body. Got: %q", rr.Body.String())
	}

	// 2. Request with valid token should pass
	ip := "192.0.2.1"
	req.RemoteAddr = ip + ":1234"
	token := passFor(secret, "Mozilla/5.0", ip, time.Now())
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.RemoteAddr = ip + ":1234"
	req.AddCookie(&http.Cookie{Name: ChallengeCookieName, Value: token})

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with valid token, got %d", rr.Code)
	}

	// 3. Request with mismatched IP should fail
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.RemoteAddr = "1.1.1.1:1234" // Different IP
	req.AddCookie(&http.Cookie{Name: ChallengeCookieName, Value: token})

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 with mismatched IP, got %d", rr.Code)
	}
}
