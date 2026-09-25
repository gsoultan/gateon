// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func securityHeadersFor(t *testing.T, preset string) (http.Header, error) {
	t.Helper()
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	mw, err := f.Create(&gateonv1.Middleware{Type: "security_headers", Config: map[string]string{"preset": preset}}, t.Name())
	if err != nil {
		return nil, err
	}
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec.Header(), nil
}

// TestSecurityHeadersPresetNoneSetsNothing: the dashboard offers "None", and
// the gateway had no case for it, so it fell through to the legacy default and
// set four headers on a route whose operator had chosen to set none -- the
// backend's own X-Frame-Options, for one, overwritten with SAMEORIGIN.
func TestSecurityHeadersPresetNoneSetsNothing(t *testing.T) {
	h, err := securityHeadersFor(t, "none")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"X-Content-Type-Options", "X-Frame-Options", "X-Xss-Protection", "Referrer-Policy"} {
		if v := h.Get(name); v != "" {
			t.Errorf("preset none set %s: %q", name, v)
		}
	}
}

// TestSecurityHeadersLegacyPresetDisablesTheXSSAuditor: "1; mode=block" asks
// for the browser XSS auditor, which modern browsers removed and whose old
// implementations could be abused to detect content cross-site. OWASP's
// guidance is 0, which the recommended and strict presets already send.
func TestSecurityHeadersLegacyPresetDisablesTheXSSAuditor(t *testing.T) {
	for _, preset := range []string{"", "legacy"} {
		h, err := securityHeadersFor(t, preset)
		if err != nil {
			t.Fatalf("preset %q: %v", preset, err)
		}
		if got := h.Get("X-Xss-Protection"); got != "0" {
			t.Errorf("preset %q: X-XSS-Protection = %q, want 0", preset, got)
		}
		if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("preset %q: X-Content-Type-Options = %q, want nosniff", preset, got)
		}
	}
}

// TestSecurityHeadersRefusesAnUnknownPreset: a misspelt preset ran as the
// legacy default while the config read as a preset someone chose.
func TestSecurityHeadersRefusesAnUnknownPreset(t *testing.T) {
	_, err := securityHeadersFor(t, "recomended")
	if err == nil || !strings.Contains(err.Error(), "preset") {
		t.Fatalf("misspelt preset: err = %v, want a config error naming preset", err)
	}
	if _, err := securityHeadersFor(t, "Strict"); err != nil {
		t.Errorf("preset in another case refused: %v", err)
	}
}
