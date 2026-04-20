package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	store := NewMemoryAPIKeyStore(keys, false)
	v := NewAPIKeyValidator(store, "X-API-Key", "api_key", AuthBaseConfig{})

	handler := v.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 1. Valid header
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "key1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// 2. Query param (rejected for non-websocket)
	req = httptest.NewRequest("GET", "/?api_key=key1", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for query param on non-websocket, got %d", rr.Code)
	}

	// 3. Query param (accepted for websocket)
	req = httptest.NewRequest("GET", "/?api_key=key1", nil)
	req.Header.Set("Upgrade", "websocket")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200 for query param on websocket, got %d", rr.Code)
	}
}

type structClaims struct {
	User string `json:"user"`
	Role string `json:"role"`
}

func (s structClaims) ToMap() map[string]any {
	return map[string]any{
		"user":  s.User,
		"roles": []string{s.Role},
	}
}

type mockVerifier struct {
	claims any
	err    error
}

func (m *mockVerifier) VerifyToken(token string) (any, error) {
	return m.claims, m.err
}

func TestPasetoAuth_StructClaims(t *testing.T) {
	claims := structClaims{User: "alice", Role: "admin"}
	verifier := &mockVerifier{claims: claims}
	mw := PasetoAuth(verifier, AuthBaseConfig{
		RequiredRoles: []string{"admin"},
	})

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		c := r.Context().Value(UserContextKey)
		if c == nil {
			t.Error("expected claims in context")
		}
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200 for struct claims with ToMap, got %d", rr.Code)
	}
}

func TestExtractToken_QueryAuth(t *testing.T) {
	// Regular GET: query token rejected
	req := httptest.NewRequest("GET", "/v1/logs?auth=test-token", nil)
	got := ExtractToken(req)
	if got != "" {
		t.Errorf("expected empty token from auth query on regular GET, got %q", got)
	}

	// WebSocket Upgrade: query token accepted
	req = httptest.NewRequest("GET", "/v1/logs?auth=test-token", nil)
	req.Header.Set("Upgrade", "websocket")
	got = ExtractToken(req)
	if got != "test-token" {
		t.Errorf("expected token from auth query on websocket upgrade, got %q", got)
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

func TestCompress_AlgorithmBrotli(t *testing.T) {
	mw := CompressWithConfig(CompressConfig{Algorithm: "br"})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"` + strings.Repeat("x", 1200) + `"}`))
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if enc := rr.Header().Get("Content-Encoding"); enc != "br" {
		t.Errorf("expected Content-Encoding: br, got %q", enc)
	}
}

func TestCompress_AlgorithmGzipSkipsWhenUnavailable(t *testing.T) {
	mw := CompressWithConfig(CompressConfig{Algorithm: "gzip"})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":"` + strings.Repeat("x", 1200) + `"}`))
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "br")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if enc := rr.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("expected no Content-Encoding when configured algorithm is unavailable, got %q", enc)
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

func TestIPFilter_AllowDeny(t *testing.T) {
	mw := IPFilter([]string{"192.168.1.0/24"}, []string{"192.168.1.100"})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.50:12345"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("allowed IP: expected 200, got %d", rr.Code)
	}

	req.RemoteAddr = "192.168.1.100:12345"
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("denied IP: expected 403, got %d", rr.Code)
	}
}

func TestIPFilter_WithXForwardedFor(t *testing.T) {
	mw := IPFilterWithClientIP([]string{"203.0.113.50"}, nil, func(r *http.Request) string {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
		addr := r.RemoteAddr
		if i := strings.LastIndex(addr, ":"); i >= 0 {
			addr = addr[:i]
		}
		return addr
	})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:80"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("XFF allowed IP: expected 200, got %d", rr.Code)
	}
}

func TestWAF_PassesNormalRequest(t *testing.T) {
	// UseCRS=false yields minimal pass-through WAF (avoids CRS file resolution in tests)
	mw, err := WAF(WAFConfig{UseCRS: false})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("normal request: expected 200, got %d", rr.Code)
	}
}

func TestTurnstile_MissingTokenReturns400(t *testing.T) {
	mw := Turnstile(TurnstileConfig{Secret: "test-secret", Methods: []string{"POST"}})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing token: expected 400, got %d", rr.Code)
	}
}

func TestTurnstile_SkipsGet(t *testing.T) {
	mw := Turnstile(TurnstileConfig{Secret: "test-secret", Methods: []string{"POST"}})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("GET skipped: expected 200, got %d", rr.Code)
	}
}

func TestGeoIP_RequiresDBPath(t *testing.T) {
	_, err := GeoIP(GeoIPConfig{})
	if err == nil {
		t.Error("expected error when db_path is empty")
	}
}

func TestHMAC_ValidSignature(t *testing.T) {
	secret := "webhook-secret"
	mw, err := HMAC(HMACConfig{Secret: secret, Header: "X-Signature-256", Prefix: "sha256=", Methods: []string{"POST"}})
	if err != nil {
		t.Fatalf("create HMAC: %v", err)
	}
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	body := []byte(`{"event":"ping"}`)
	mac := hmacSHA256Hex([]byte(secret), body)
	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-Signature-256", "sha256="+mac)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("valid signature: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHMAC_InvalidSignature(t *testing.T) {
	mw, _ := HMAC(HMACConfig{Secret: "secret", Methods: []string{"POST"}})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/", strings.NewReader("body"))
	req.Header.Set("X-Signature-256", "sha256="+strings.Repeat("00", 32))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("invalid signature: expected 401, got %d", rr.Code)
	}
}

func TestHostFilter(t *testing.T) {
	mw := HostFilter("admin.example.com")
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		host       string
		expectCode int
	}{
		{"Match", "admin.example.com", http.StatusOK},
		{"Match with Port", "admin.example.com:8080", http.StatusOK},
		{"Mismatch", "other.example.com", http.StatusForbidden},
		{"Mismatch with Port", "other.example.com:8080", http.StatusForbidden},
		{"Case Insensitive", "ADMIN.EXAMPLE.COM", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.expectCode {
				t.Errorf("%s: expected %d, got %d", tt.name, tt.expectCode, rr.Code)
			}
		})
	}
}

func hmacSHA256Hex(secret, body []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func TestWasm_EmptyBlob(t *testing.T) {
	_, err := Wasm(t.Context(), nil)
	if err == nil {
		t.Error("expected error for empty wasm blob")
	}
}

func TestWasm_MinimalValid(t *testing.T) {
	// Minimal WASM module header: \x00asm\x01\x00\x00\x00
	minimalWasm := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	mw, err := Wasm(t.Context(), minimalWasm)
	if err != nil {
		t.Fatalf("failed to create wasm middleware: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestErrors_ReplacesBody(t *testing.T) {
	cfg := ErrorsConfig{
		StatusCodes: []int{http.StatusNotFound},
		CustomPages: map[int]string{
			http.StatusNotFound: "<html>Custom 404</html>",
		},
	}
	mw := Errors(cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("original body"))
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
	if rr.Body.String() != "<html>Custom 404</html>" {
		t.Errorf("expected custom body, got %q", rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("expected text/html, got %q", ct)
	}
}
