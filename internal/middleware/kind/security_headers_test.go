package kind

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeadersUpgradeInsecureRequests(t *testing.T) {
	const upgrade = "upgrade-insecure-requests"

	tests := []struct {
		name         string
		preset       string
		tls          bool
		fwdProto     string
		wantUpgrade  bool
		wantHSTS     bool
		wantCSPEmpty bool
	}{
		{name: "RecommendedPlainHTTP", preset: "recommended", wantUpgrade: false, wantHSTS: false},
		{name: "RecommendedTLS", preset: "recommended", tls: true, wantUpgrade: true, wantHSTS: true},
		{name: "RecommendedForwardedHTTPS", preset: "recommended", fwdProto: "https", wantUpgrade: true, wantHSTS: true},
		{name: "StrictPlainHTTP", preset: "strict", wantUpgrade: false, wantHSTS: false},
		{name: "StrictTLS", preset: "strict", tls: true, wantUpgrade: true, wantHSTS: true},
		{name: "DefaultNoCSP", preset: "", wantCSPEmpty: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := SecurityHeaders(SecurityHeadersConfig{Preset: tc.preset})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if tc.fwdProto != "" {
				req.Header.Set("X-Forwarded-Proto", tc.fwdProto)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			csp := rec.Header().Get("Content-Security-Policy")
			if tc.wantCSPEmpty {
				if csp != "" {
					t.Fatalf("expected no CSP for default preset, got %q", csp)
				}
				return
			}
			if csp == "" {
				t.Fatalf("expected CSP to be set for preset %q", tc.preset)
			}
			if got := strings.Contains(csp, upgrade); got != tc.wantUpgrade {
				t.Errorf("CSP contains %q = %v; want %v (csp=%q)", upgrade, got, tc.wantUpgrade, csp)
			}
			if got := rec.Header().Get("Strict-Transport-Security") != ""; got != tc.wantHSTS {
				t.Errorf("HSTS present = %v; want %v", got, tc.wantHSTS)
			}
		})
	}
}
