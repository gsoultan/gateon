// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/stretchr/testify/assert"
)

func TestJA4PlusMitigationE2E(t *testing.T) {
	// Initialize telemetry store
	dbPath := filepath.Join(t.TempDir(), "ja4plus_e2e_test.db")
	_ = telemetry.InitPathStatsStore("sqlite:"+dbPath, 1)
	defer telemetry.ClosePathStatsStore(context.Background())

	// Define a backend
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Wrap with middleware chain
	handler := middleware.Chain(
		middleware.WithRequestState("test-ep", "test", false),
		middleware.UserMitigation(),
	)(middleware.ThreatRecognition("test-route")(backend))

	ja4 := "t13d1516h2_8c224e757c16_0d2e82e5b8e9"

	// 1. Initial request (Clean)
	req1 := httptest.NewRequest("GET", "/safe", nil)
	req1.Header.Set("X-JA4-Fingerprint", ja4)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)

	// 2. Malicious request (Trigger Mitigation)
	// We'll use a gambling keyword to trigger ThreatRecognition
	req2 := httptest.NewRequest("GET", "/search?q=online+casino", nil)
	req2.Header.Set("X-JA4-Fingerprint", ja4)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code) // ThreatRecognition just detects by default

	// Manually trigger mitigation in telemetry for the fingerprint
	ja4h := telemetry.GenerateJA4H(req2)
	ja4plus := ja4 + "_" + ja4h
	telemetry.MarkUserMitigated(ja4plus, "JA4+", "Malicious behavior detected", "gambling")

	// Wait for cache/DB update
	time.Sleep(100 * time.Millisecond)

	// 3. Subsequent request (Should be blocked by JA4+)
	req3 := httptest.NewRequest("GET", "/safe", nil)
	req3.Header.Set("X-JA4-Fingerprint", ja4)
	// Must have SAME headers to get same JA4H
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)

	assert.Equal(t, http.StatusForbidden, rec3.Code)
	assert.Contains(t, rec3.Body.String(), "Compromised Fingerprint")

	// 4. Remove mitigation
	telemetry.MarkUserUnmitigated(ja4plus)
	telemetry.ResetReputation(ja4plus)
	time.Sleep(2 * time.Second)

	// 5. Request after unmitigation (Should be allowed)
	req4 := httptest.NewRequest("GET", "/safe", nil)
	req4.Header.Set("X-JA4-Fingerprint", ja4)
	rec4 := httptest.NewRecorder()
	handler.ServeHTTP(rec4, req4)
	assert.Equal(t, http.StatusOK, rec4.Code)
}
