package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

func TestJWTValidator(t *testing.T) {
	secret := []byte("test-secret")
	cfg := JWTConfig{
		Issuer:   "gateon",
		Audience: "api",
		Secret:   secret,
	}
	v, _ := NewJWTValidator(cfg)

	handler := v.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		claims := r.Context().Value(UserContextKey).(jwt.MapClaims)
		if claims["sub"] != "user123" {
			t.Errorf("expected sub user123, got %v", claims["sub"])
		}
	}))

	// 1. Valid Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "gateon",
		"aud": "api",
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString(secret)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// 2. Expired Token
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "gateon",
		"aud": "api",
		"sub": "user123",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	expiredTokenString, _ := expiredToken.SignedString(secret)

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+expiredTokenString)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for expired token, got %d", rr.Code)
	}
}

func TestAPIKeyValidator(t *testing.T) {
	keys := map[string]string{
		"key1": "tenant1",
	}
	v := NewAPIKeyValidator(keys)

	handler := v.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		tid := r.Context().Value(TenantIDContextKey).(string)
		if tid != "tenant1" {
			t.Errorf("expected tenant1, got %s", tid)
		}
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "key1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "invalid")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rr.Code)
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(rate.Limit(1), 1) // 1 req/s, burst 1
	handler := rl.Handler(PerIP)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"

	// First request - OK
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", rr.Code)
	}

	// Second request (immediate) - Too Many Requests
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d", rr.Code)
	}
}

func TestRewrite(t *testing.T) {
	cfg := RewriteConfig{
		Path: "/new-path",
		AddQuery: map[string]string{
			"foo": "bar",
		},
	}
	mw := Rewrite(cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/new-path" {
			t.Errorf("expected /new-path, got %s", r.URL.Path)
		}
		if r.URL.Query().Get("foo") != "bar" {
			t.Errorf("expected foo=bar, got %s", r.URL.Query().Get("foo"))
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/old-path", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
}

func TestAddPrefix(t *testing.T) {
	mw := AddPrefix("/api")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/users" {
			t.Errorf("expected /api/users, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/users", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
}

func TestStripPrefix(t *testing.T) {
	mw := StripPrefix([]string{"/api"})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users" {
			t.Errorf("expected /users, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/users", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
}
