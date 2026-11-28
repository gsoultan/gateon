// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/kind"
)

// TestABrowserIntegrityRefusalDoesNotNameItsCheck is ADR 0106: the refusal
// said "Browser Integrity Check Failed", which tells a bot what to add (the
// Sec-Fetch headers) before its next try. It says what every refusal says.
func TestABrowserIntegrityRefusalDoesNotNameItsCheck(t *testing.T) {
	handler := BotManagement(BotManagementConfig{
		Enabled:                true,
		EnableBrowserIntegrity: true,
		RouteID:                "bot-uniform-route",
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.93:4321"
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("integrity failure: got %d, want 403", rr.Code)
	}
	if got := rr.Body.String(); got != kind.RefusalBody {
		t.Errorf("the refusal's body is %q, want %q", got, kind.RefusalBody)
	}
}
