// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
)

// The embedded auth.Service supplies the method set this stub does not care
// about. It is embedded rather than implemented because isLogsRequestAuthorized
// takes an auth.Service: the parameter used to be the narrower
// middleware.TokenVerifier, which is part of how a nil-comparison on it stayed
// invisible to check-security-invariants.
type testTokenVerifier struct {
	auth.Service
	token  string
	claims *auth.Claims
	err    error
}

func (v testTokenVerifier) VerifyToken(token string) (any, error) {
	if token != v.token {
		return nil, errors.New("invalid token")
	}
	return v.claims, v.err
}

func TestIsLogsRequestAuthorized(t *testing.T) {
	t.Run("allows when request already has authenticated user context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/logs", nil)
		claims := &auth.Claims{Role: auth.RoleAdmin}
		req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey, claims))

		if !isLogsRequestAuthorized(req, testTokenVerifier{token: "expected"}) {
			t.Fatal("expected request with authenticated context to be authorized")
		}
	})

	// This subtest asserted the opposite until 2026-09-04: a nil verifier
	// authorized the log stream, on the reading that a missing auth service
	// means auth is disabled. auth.Available's documentation says a nil service
	// and a Holder that Setup has not filled are both unusable and "both must
	// deny", and the first-run hardening moved the rest of the management plane
	// to that position. This was the last place still reading an absent service
	// as permission.
	//
	// Nothing shipped depended on the old behaviour: the single NewServer call
	// site passes WithAuthManager, which always wraps in a Holder, so the
	// interface was never nil in the binary. The expectation was reachable only
	// from a test.
	t.Run("denies when the auth service cannot answer", func(t *testing.T) {
		for _, tt := range []struct {
			name     string
			verifier auth.Service
		}{
			{"no service at all", nil},
			{"a Holder Setup never filled", auth.NewHolder(nil)},
		} {
			t.Run(tt.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/v1/logs", nil)
				// A credential is offered, so a denial cannot be mistaken for
				// "nothing was presented".
				req.Header.Set("Authorization", "Bearer some-token")

				if isLogsRequestAuthorized(req, tt.verifier) {
					t.Fatal("the system log stream was authorized while auth could not answer")
				}
			})
		}
	})

	t.Run("denies when token missing and no authenticated context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/logs", nil)

		if isLogsRequestAuthorized(req, testTokenVerifier{token: "expected"}) {
			t.Fatal("expected request without token to be denied")
		}
	})

	t.Run("allows with valid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/logs?auth=expected", nil)
		req.Header.Set("Upgrade", "websocket")
		claims := &auth.Claims{Role: auth.RoleAdmin}

		if !isLogsRequestAuthorized(req, testTokenVerifier{token: "expected", claims: claims}) {
			t.Fatal("expected request with valid token to be authorized")
		}
	})

	t.Run("denies with invalid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/logs?auth=wrong", nil)
		req.Header.Set("Upgrade", "websocket")

		if isLogsRequestAuthorized(req, testTokenVerifier{token: "expected"}) {
			t.Fatal("expected request with invalid token to be denied")
		}
	})
}
