package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

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
	f := NewFactory(nil, store, nil, ".")

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
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tc.expectCode {
				t.Errorf("expected status %d, got %d", tc.expectCode, rr.Code)
			}
		})
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
			f := NewFactory(nil, &mockGlobalConfigStore{config: cfg}, nil, ".")
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
