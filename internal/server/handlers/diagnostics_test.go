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

type testTokenVerifier struct {
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

	t.Run("allows when auth manager is disabled", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/logs", nil)

		if !isLogsRequestAuthorized(req, nil) {
			t.Fatal("expected request to be authorized when verifier is nil")
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
