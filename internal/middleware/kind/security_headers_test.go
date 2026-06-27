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
		// X-Forwarded-Proto from an untrusted peer must NOT be believed (it is
		// client-spoofable); detection now requires GATEON_TRUSTED_PROXIES. The
		// fail-safe outcome is simply that HTTPS-only headers are not emitted.
		{name: "ForwardedHTTPSUntrustedIgnored", preset: "recommended", fwdProto: "https", wantUpgrade: false, wantHSTS: false},
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

// TestSecurityHeadersExtraImgSrc verifies that ExtraImgSrc widens only the
// img-src directive (so the management UI can load basemap tiles) without
// touching script-src/connect-src or leaking into the default preset's CSP.
func TestSecurityHeadersExtraImgSrc(t *testing.T) {
	const tileHost = "https://*.basemaps.cartocdn.com"

	t.Run("AddsToImgSrcOnly", func(t *testing.T) {
		h := SecurityHeaders(SecurityHeadersConfig{
			Preset:      "recommended",
			ExtraImgSrc: []string{tileHost},
		})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		csp := rec.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "img-src 'self' data: "+tileHost+";") {
			t.Errorf("expected img-src to include %q; csp=%q", tileHost, csp)
		}
		if strings.Contains(csp, "script-src 'self' "+tileHost) || strings.Contains(csp, "connect-src 'self' "+tileHost) {
			t.Errorf("tile host leaked beyond img-src; csp=%q", csp)
		}
	})

	t.Run("BaselineUnaffectedWhenEmpty", func(t *testing.T) {
		h := SecurityHeaders(SecurityHeadersConfig{Preset: "recommended"})(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		csp := rec.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "img-src 'self' data:;") {
			t.Errorf("baseline img-src changed; csp=%q", csp)
		}
		if strings.Contains(csp, "cartocdn") {
			t.Errorf("baseline CSP must not mention tile host; csp=%q", csp)
		}
	})
}
