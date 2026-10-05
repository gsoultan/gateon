// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestACORSViolationIsObserved: the CORS middleware lets the request through
// and records a cors_violation, which was held against its source (review 3,
// F3). The Origin header is written by a browser that another site's page
// made send the request -- the honeypot's unattributed shape -- so holding it
// made the visitor a correlation signal and, under a block playbook at
// threshold 0, shunned it. A control that lets the request through records
// Observed (ADR 0059); the stored row has to say so too, for the analysis
// engine.
func TestACORSViolationIsObserved(t *testing.T) {
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "cors.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(t.Context()) })
	threats := telemetry.ThreatBroadcaster.Subscribe()
	t.Cleanup(func() { telemetry.ThreatBroadcaster.Unsubscribe(threats) })

	h := CORS(CORSConfig{AllowedOrigins: []string{"https://app.example.com"}})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.RemoteAddr = "198.51.100.41:5000"
	req.Header.Set("Origin", "https://evil.example.net")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	telemetry.FlushThreats()

	if rr.Code != http.StatusOK {
		t.Fatalf("the CORS middleware answered %d; it lets the request through", rr.Code)
	}
	if len(threats) != 1 {
		t.Fatalf("%d threats were recorded, want the one cors_violation", len(threats))
	}
	th := <-threats
	if th.Type != "cors_violation" || !th.Observed || th.HeldAgainstSource() {
		t.Errorf("recorded %s observed=%v held=%v, want an observed cors_violation held against nobody",
			th.Type, th.Observed, th.HeldAgainstSource())
	}
	stored, err := telemetry.GetSecurityThreatByID(t.Context(), th.ID)
	if err != nil || stored == nil {
		t.Fatalf("read the stored violation back: %v", err)
	}
	if stored.HeldAgainstSource() {
		t.Errorf("the stored violation is held against its source (observed=%v)", stored.Observed)
	}
}
