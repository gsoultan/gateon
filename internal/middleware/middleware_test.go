package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
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
	v := NewAPIKeyValidator(keys, "X-API-Key")

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

func TestBasicAuth(t *testing.T) {
	mw := BasicAuth("admin", "secret")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("basic auth: expected 200, got %d", rr.Code)
	}

	req = httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "wrong")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("basic auth wrong pass: expected 401, got %d", rr.Code)
	}
}

func TestBasicAuthUsers(t *testing.T) {
	mw, err := BasicAuthUsers("u1:p1,u2:p2", "Test")
	if err != nil {
		t.Fatal(err)
	}
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("u1", "p1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("basic auth users: expected 200, got %d", rr.Code)
	}

	req = httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("u2", "p2")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("basic auth users u2: expected 200, got %d", rr.Code)
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

func TestCompress(t *testing.T) {
	mw := Compress()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"` + strings.Repeat("x", 1200) + `"}`)) // >1024 bytes
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if enc := rr.Header().Get("Content-Encoding"); enc != "gzip" {
		t.Errorf("expected Content-Encoding: gzip, got %q", enc)
	}
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

func TestForwardAuth(t *testing.T) {
	// Auth server: 200 = pass, 401 = fail
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth-Token") == "valid" {
			w.Header().Set("X-Forwarded-User", "user1")
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer authSrv.Close()

	mw, err := ForwardAuth(ForwardAuthConfig{
		Address:             authSrv.URL,
		AuthResponseHeaders: []string{"X-Forwarded-User"},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok:" + r.Header.Get("X-Forwarded-User")))
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Auth-Token", "valid")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "user1") {
		t.Errorf("expected body to contain user1, got %q", rr.Body.String())
	}

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Auth-Token", "invalid")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
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
