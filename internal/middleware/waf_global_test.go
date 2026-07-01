package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/security/waf"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func init() {
	// Initialize the WAF store for tests that use the WAF middleware
	_ = waf.InitStore("sqlite::memory:")
}

// TestCreateGlobalWAF_LoadsCRSWithDefaultFlags is the regression guard for the
// root cause of "WAF detections = 0": the legacy per-route merge wrote "false"
// for every unset category boolean, which the parser mapped to Disable*=true and
// silently stripped the entire OWASP CRS attack ruleset. CreateGlobalWAF must NOT
// fall into that trap — with WAF enabled and all category flags at their zero
// value, the gateway-wide WAF must still load CRS and block a SQLi attack.
func TestCreateGlobalWAF_LoadsCRSWithDefaultFlags(t *testing.T) {
	store := &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{
		Waf: &gateonv1.WafConfig{
			Enabled:       true,
			UseCrs:        true,
			ParanoiaLevel: 1,
			// All Sqli/Xss/Lfi/... left false (proto zero value) — the trap scenario.
		},
	}}
	f := NewFactory(nil, store, nil, nil, ".")

	mw, err := f.CreateGlobalWAF()
	if err != nil {
		t.Fatalf("CreateGlobalWAF: %v", err)
	}
	if mw == nil {
		t.Fatal("expected a global WAF middleware, got nil")
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		url        string
		expectCode int
	}{
		{name: "safe request passes", url: "/?name=test", expectCode: http.StatusOK},
		{
			name:       "SQLi blocked (proves CRS rules loaded)",
			url:        "/?id=1%27%20OR%20%271%27%3D%271%20--%20",
			expectCode: http.StatusForbidden,
		},
		{
			name:       "XSS blocked (proves CRS rules loaded)",
			url:        "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
			expectCode: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, strings.NewReader(""))
			// Force low reputation for security tests that expect blocks at score 5.
			req.Header.Set("X-Gateon-Test-Reputation", "0")
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tc.expectCode {
				t.Errorf("expected status %d, got %d", tc.expectCode, rr.Code)
			}
		})
	}
}

// TestCreateGlobalWAF_AllowsGRPC is the regression guard for the gRPC 403:
// once Phase B injected the full-CRS global WAF into every route, native gRPC
// and gRPC-Web requests were rejected by REQUEST-920 rule 920420 because their
// content types are absent from the CRS default tx.allowed_request_content_type
// list (a single critical hit reaches the default anomaly threshold of 5 and
// 949110 denies with 403). The WAF must let the legitimate gRPC transport pass
// while still inspecting headers/URI.
func TestCreateGlobalWAF_AllowsGRPC(t *testing.T) {
	store := &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{
		Waf: &gateonv1.WafConfig{Enabled: true, UseCrs: true, ParanoiaLevel: 1},
	}}
	f := NewFactory(nil, store, nil, nil, ".")
	f.SetRouteType("grpc") // trusted route type unlocks the gRPC transport relaxations

	mw, err := f.CreateGlobalWAF()
	if err != nil {
		t.Fatalf("CreateGlobalWAF: %v", err)
	}

	reached := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	grpcCTs := []string{
		"application/grpc",
		"application/grpc+proto",
		"application/grpc-web+proto",
		"application/grpc-web-text",
	}
	for _, ct := range grpcCTs {
		t.Run(ct, func(t *testing.T) {
			reached = false
			req := httptest.NewRequest(http.MethodPost, "/helloworld.Greeter/SayHello", strings.NewReader(""))
			req.Header.Set("Content-Type", ct)
			req.Header.Set("Te", "trailers")
			// Binary protobuf metadata is delivered as high-entropy "-bin"
			// headers — the entropy fast-path must not trip on it.
			req.Header.Set("x-trace-bin", strings.Repeat("AQIDBAUGBwgJ", 16))
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK || !reached {
				t.Errorf("gRPC request with %s was blocked: status=%d reached=%v", ct, rr.Code, reached)
			}
		})
	}
}

// TestCreateGlobalWAF_GRPCRelaxationNotBypassableByHeader is the security guard
// for the gRPC fix: the gRPC transport relaxations (allowed content type, removal
// of rule 920180, request-body-access Off, fast-path skip) must be gated on the
// trusted route type, NOT the client Content-Type. A request to a non-gRPC route
// that spoofs "Content-Type: application/grpc" must still be fully inspected, so a
// SQLi payload in the body is blocked rather than waved through.
func TestCreateGlobalWAF_GRPCRelaxationNotBypassableByHeader(t *testing.T) {
	store := &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{
		Waf: &gateonv1.WafConfig{
			Enabled: true, UseCrs: true, ParanoiaLevel: 1,
			// Force CRS to inspect the request body so the bypass would be observable.
			RequestBodyLimit: 1 << 20,
		},
	}}

	// HTTP route (no gRPC type): the relaxation must NOT apply.
	f := NewFactory(nil, store, nil, nil, ".")
	f.SetRouteType("http")
	mw, err := f.CreateGlobalWAF()
	if err != nil {
		t.Fatalf("CreateGlobalWAF: %v", err)
	}
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := "username=admin'+OR+1=1--+-&password=x"
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	// Force low reputation so score 10 blocks (threshold is 5).
	req.Header.Set("X-Gateon-Test-Reputation", "0")
	// Attacker spoofs the gRPC content type to try to dodge body inspection.
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("spoofed Content-Type bypassed the WAF on an HTTP route: got status %d, want 403", rr.Code)
	}
}

// TestCreateGlobalWAF_DisabledReturnsNil verifies the gateway-wide WAF is only
// built when explicitly enabled, so it stays opt-in and never blocks traffic on
// a default install.
func TestCreateGlobalWAF_DisabledReturnsNil(t *testing.T) {
	cases := map[string]*gateonv1.GlobalConfig{
		"nil waf":      {},
		"waf disabled": {Waf: &gateonv1.WafConfig{Enabled: false, UseCrs: true}},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			f := NewFactory(nil, &mockGlobalConfigStore{config: cfg}, nil, nil, ".")
			mw, err := f.CreateGlobalWAF()
			if err != nil {
				t.Fatalf("CreateGlobalWAF: %v", err)
			}
			if mw != nil {
				t.Error("expected nil middleware when global WAF is disabled")
			}
		})
	}
}
