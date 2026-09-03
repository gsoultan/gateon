// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// stubRevocationStore reports whatever it is told, including a backend failure,
// which is the case a real Redis outage produces and the one nothing exercised.
type stubRevocationStore struct {
	revoked bool
	err     error
	asked   []string
}

func (s *stubRevocationStore) IsRevoked(_ context.Context, jti string) (bool, error) {
	s.asked = append(s.asked, jti)
	return s.revoked, s.err
}

func (s *stubRevocationStore) Revoke(context.Context, string, time.Duration) error { return nil }

var revocationTestSecret = []byte("test-secret-not-used-anywhere-else")

// signedToken mints a token this validator will accept on signature alone, so
// that whatever the test observes comes from revocation and nothing else.
func signedToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(revocationTestSecret)
	if err != nil {
		t.Fatalf("signing the test token: %v", err)
	}
	return s
}

// serveWithRevocation runs one request through the JWT handler and reports what
// the client saw and whether the request reached the protected handler.
func serveWithRevocation(t *testing.T, store RevocationStore, claims jwt.MapClaims) (status int, body string, reached bool) {
	t.Helper()
	v, err := NewJWTValidator(JWTConfig{Secret: revocationTestSecret, RevocationStore: store})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+signedToken(t, claims))
	rec := httptest.NewRecorder()
	v.Handler(next).ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), reached
}

// TestRevocationCheckFailsClosed is the regression test for a revocation check
// that failed open.
//
// validateToken called IsRevoked as `revoked, _ :=`, discarding the error.
// RedisRevocationStore returns (false, err) when Redis is unreachable, so every
// revoked token was accepted for as long as the store was down — a restart, a
// network blip, a timeout or a bad password. Revocation is the control you reach
// for after a compromise, which makes an outage exactly the wrong moment for it
// to stop enforcing, and the operator had explicitly turned it on.
func TestRevocationCheckFailsClosed(t *testing.T) {
	claims := jwt.MapClaims{"sub": "user-1", "jti": "token-1", "exp": time.Now().Add(time.Hour).Unix()}

	t.Run("backend error denies", func(t *testing.T) {
		store := &stubRevocationStore{err: errors.New("dial tcp 127.0.0.1:6379: connect: connection refused")}
		status, _, reached := serveWithRevocation(t, store, claims)

		if reached {
			t.Error("request reached the protected handler while revocation status was unknown")
		}
		if status != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", status, http.StatusUnauthorized)
		}
		if len(store.asked) != 1 || store.asked[0] != "token-1" {
			t.Errorf("store was asked %v, want exactly [token-1]", store.asked)
		}
	})

	t.Run("backend error is not leaked to the client", func(t *testing.T) {
		store := &stubRevocationStore{err: errors.New("dial tcp 127.0.0.1:6379: connect: connection refused")}
		_, body, _ := serveWithRevocation(t, store, claims)

		// HandleFailure writes err.Error() straight into the response, so a
		// wrapped driver error would hand the caller the address and port of
		// an internal service.
		for _, leak := range []string{"6379", "127.0.0.1", "dial tcp", "connection refused"} {
			if strings.Contains(body, leak) {
				t.Errorf("response body leaks %q to the client: %s", leak, body)
			}
		}
	})

	t.Run("revoked token denies", func(t *testing.T) {
		store := &stubRevocationStore{revoked: true}
		status, _, reached := serveWithRevocation(t, store, claims)
		if reached {
			t.Error("a revoked token reached the protected handler")
		}
		if status != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", status, http.StatusUnauthorized)
		}
	})

	t.Run("healthy store with a live token allows", func(t *testing.T) {
		store := &stubRevocationStore{}
		status, _, reached := serveWithRevocation(t, store, claims)
		if !reached {
			t.Error("a live token was rejected by a healthy revocation store")
		}
		if status != http.StatusOK {
			t.Errorf("status = %d, want %d", status, http.StatusOK)
		}
	})
}
