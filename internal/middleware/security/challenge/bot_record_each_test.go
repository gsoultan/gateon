// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestEveryBotRefusalIsStored: a browser-integrity refusal was filed under
// "bot-<label>-<route>-<ip>", the same ID for every refusal of one client, so
// the store's primary key kept the first and dropped the rest. The Threats
// page then showed one refusal for a client the gateway had refused many times.
func TestEveryBotRefusalIsStored(t *testing.T) {
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "bot-each.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	defer telemetry.ClosePathStatsStore(context.Background())

	const refusals = 3
	handler := BotManagement(BotManagementConfig{
		Enabled:                true,
		EnableBrowserIntegrity: true,
		RouteID:                "bot-each-route",
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	for range refusals {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "198.51.100.92:4321"
		// Claims a modern browser and sends none of its Sec-Fetch headers.
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("integrity failure: got %d, want 403", rr.Code)
		}
	}
	telemetry.FlushThreats()

	got := telemetry.CountSecurityThreats(t.Context(), &telemetry.ThreatFilter{Search: "198.51.100.92"})
	if got != refusals {
		t.Fatalf("stored %d bot refusals, want %d: one row per refusal", got, refusals)
	}
}
