// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

func TestWAF_PHPAttacks(t *testing.T) {
	mw, err := WAF(WAFConfig{
		DisablePHP: false,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		method     string
		url        string
		body       string
		expectCode int
	}{
		{
			name:       "Safe request",
			method:     "GET",
			url:        "/?name=test",
			expectCode: http.StatusOK,
		},
		{
			name:       "PHP injection in query",
			method:     "GET",
			url:        "/?test=%3C%3Fphp%20system('id')%3B%20%3F%3E",
			expectCode: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tc.expectCode {
				t.Errorf("expected status %d, got %d", tc.expectCode, rr.Code)
			}
		})
	}
}

func TestWAF_NodeJSAttacks(t *testing.T) {
	mw, err := WAF(WAFConfig{
		DisableNodeJS: false,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		method     string
		url        string
		body       string
		expectCode int
	}{
		// Unambiguous Node.js RCE — caught by ruleset rule 1100016.
		{
			name:       "NodeJS/require child_process exec",
			method:     "GET",
			url:        "/?t=require('child_process').execSync('id')",
			expectCode: http.StatusForbidden,
		},
		{
			name:       "NodeJS/constructor sandbox escape",
			method:     "GET",
			url:        "/?t=e.constructor.constructor('return%20process')()",
			expectCode: http.StatusForbidden,
		},
		{
			name:       "NodeJS/mainModule require pivot",
			method:     "GET",
			url:        "/?t=global.process.mainModule.require('fs')",
			expectCode: http.StatusForbidden,
		},
		// Bare "process.env" is a plain property access that appears in docs and
		// config text. It must NOT be blocked — doing so was a false-positive
		// class of the retired fast path.
		{
			name:       "NodeJS/bare process.env is not an attack",
			method:     "GET",
			url:        "/?msg=process.env%20holds%20the%20config",
			expectCode: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tc.expectCode {
				t.Errorf("expected status %d, got %d", tc.expectCode, rr.Code)
			}
		})
	}
}

func TestWAF_IPReputation(t *testing.T) {
	// Reputation no longer travels through a request header. Under Coraza it
	// was written into X-Gateon-Reputation and read back by a SecRule, which
	// meant gateon had to strip six headers from client input on every request
	// so a client could not assert its own reputation. It now crosses as a
	// resolver value, which removes the vector rather than defending it.
	mw, err := WAF(WAFConfig{
		EnableIPReputation: true,
		ParanoiaLevel:      1,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// A hostile behavioural score reaches rule 1910002 through the resolver.
	req := httptest.NewRequest("GET", "/", nil)
	rs := &request.RequestState{Reputation: 5}
	req = req.WithContext(context.WithValue(req.Context(), request.RequestStateContextKey{}, rs))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status 403 (IP reputation), got %d", rr.Code)
	}

	// A client cannot talk its way out of it, nor into someone else's block:
	// the header is not an input any more.
	good := httptest.NewRequest("GET", "/", nil)
	good.Header.Set("X-Gateon-Reputation", "0")
	goodState := &request.RequestState{Reputation: 100}
	good = good.WithContext(context.WithValue(good.Context(), request.RequestStateContextKey{}, goodState))
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, good)

	if rr.Code != http.StatusOK {
		t.Errorf("a spoofed reputation header changed the verdict: got %d", rr.Code)
	}
}
