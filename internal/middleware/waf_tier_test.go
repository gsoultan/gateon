package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func buildTierWAF(t *testing.T, waf *gateonv1.WafConfig) http.Handler {
	t.Helper()
	store := &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{Waf: waf}}
	f := NewFactory(nil, store, nil, nil, ".")
	mw, err := f.CreateGlobalWAF()
	if err != nil {
		t.Fatalf("CreateGlobalWAF: %v", err)
	}
	if mw == nil {
		t.Fatal("expected a global WAF middleware, got nil")
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
}

func doGet(t *testing.T, h http.Handler, url string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, strings.NewReader(""))
	// Force low reputation for security tests that expect blocks at score 5.
	req.Header.Set("X-Gateon-Test-Reputation", "0")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// TestWAFTier_MinimalStillBlocksCoreAttacks ensures the minimal tier keeps the
// core request-phase protections (SQLi/XSS) even though it drops the heavier
// rule groups. Lowering footprint must never silently disable core coverage.
func TestWAFTier_MinimalStillBlocksCoreAttacks(t *testing.T) {
	h := buildTierWAF(t, &gateonv1.WafConfig{Enabled: true, UseCrs: true, Tier: "minimal"})

	if code := doGet(t, h, "/?name=test"); code != http.StatusOK {
		t.Errorf("safe request: expected 200, got %d", code)
	}
	if code := doGet(t, h, "/?id=1%27%20OR%20%271%27%3D%271%20--%20"); code != http.StatusForbidden {
		t.Errorf("SQLi under minimal tier: expected 403, got %d", code)
	}
	if code := doGet(t, h, "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"); code != http.StatusForbidden {
		t.Errorf("XSS under minimal tier: expected 403, got %d", code)
	}
}

// TestWAFTier_EnterpriseBuildsAndBlocks ensures the enterprise tier (which turns
// on response-phase inspection + malware/ransomware) still compiles and enforces
// request-phase attacks.
func TestWAFTier_EnterpriseBuildsAndBlocks(t *testing.T) {
	h := buildTierWAF(t, &gateonv1.WafConfig{Enabled: true, UseCrs: true, Tier: "enterprise"})
	if code := doGet(t, h, "/?id=1%27%20OR%20%271%27%3D%271%20--%20"); code != http.StatusForbidden {
		t.Errorf("SQLi under enterprise tier: expected 403, got %d", code)
	}
}

// TestWAFTier_ProfileEnvDrivesTier verifies GATEON_PROFILE selects the WAF tier
// when WafConfig.tier is unset.
func TestWAFTier_ProfileEnvDrivesTier(t *testing.T) {
	t.Setenv("GATEON_PROFILE", "minimal")
	h := buildTierWAF(t, &gateonv1.WafConfig{Enabled: true, UseCrs: true})
	if code := doGet(t, h, "/?id=1%27%20OR%20%271%27%3D%271%20--%20"); code != http.StatusForbidden {
		t.Errorf("SQLi with profile=minimal: expected 403, got %d", code)
	}
}

// TestWAFFastPath_BlocksHeaderInjection proves the extended fast-path catches a
// signature smuggled through the User-Agent header before the CRS engine runs.
func TestWAFFastPath_BlocksHeaderInjection(t *testing.T) {
	h := buildTierWAF(t, &gateonv1.WafConfig{Enabled: true, UseCrs: true, Tier: "standard"})

	req := httptest.NewRequest(http.MethodGet, "/", strings.NewReader(""))
	req.Header.Set("User-Agent", "sqlmap/1.0 UNION SELECT password FROM users")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("header injection via User-Agent: expected 403, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Fast-Path") {
		t.Errorf("expected fast-path block message, got %q", rr.Body.String())
	}
}
