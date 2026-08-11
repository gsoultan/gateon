// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

func TestTraceTimingBreakdown(t *testing.T) {
	// Force standard profile to enable trace store
	t.Setenv("GATEON_PROFILE", "standard")

	// Ensure store is fresh
	_ = telemetry.ClosePathStatsStore(context.Background())

	// Initialize telemetry store for the test
	tmpDir := t.TempDir()
	_ = telemetry.InitPathStatsStore("sqlite:"+tmpDir+"/test_timing.db", 1)
	defer func() { _ = telemetry.ClosePathStatsStore(context.Background()) }()

	// Mock route label
	routeLabel := "test-route"

	// Create a chain similar to ApplyRouteMiddlewares
	// outermost: Metrics -> Timing Wrapper -> next (mock proxy)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rs := request.GetRequestState(r); rs != nil {
			rs.TServiceStart = time.Now().UnixNano()
			// Simulate some service work
			time.Sleep(10 * time.Millisecond)
			rs.TServiceEnd = time.Now().UnixNano()
		}
		w.WriteHeader(http.StatusOK)
	})

	timingWrapper := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rs := request.GetRequestState(r); rs != nil {
				rs.TMiddlewareStart = time.Now().UnixNano()
			}
			// Simulate some middleware work
			time.Sleep(5 * time.Millisecond)
			next.ServeHTTP(w, r)
			if rs := request.GetRequestState(r); rs != nil {
				rs.TMiddlewareEnd = time.Now().UnixNano()
			}
		})
	}

	// Chain: Metrics -> Timing Wrapper -> Inner
	handler := Metrics(routeLabel)(timingWrapper(inner))

	// Outermost: RequestState initialization (as in entrypoint)
	finalHandler := WithRequestState("ep-1", "test-ep", false)(handler)

	// Create request
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	rr := httptest.NewRecorder()

	// Execute
	finalHandler.ServeHTTP(rr, req)

	// Wait for asynchronous trace flush
	var traces []*telemetry.TraceRecord
	for i := 0; i < 10; i++ {
		time.Sleep(100 * time.Millisecond)
		traces = telemetry.GetTraces(context.Background(), 1)
		if len(traces) > 0 {
			break
		}
	}

	if len(traces) == 0 {
		t.Fatal("no traces recorded after wait")
	}

	tr := traces[0]

	// Verify timings are non-zero (or at least reasonable)
	if tr.MiddlewareDelay == 0 {
		t.Errorf("expected non-zero middleware delay, got 0")
	}
	if tr.ServiceDelay == 0 {
		t.Errorf("expected non-zero service delay, got 0")
	}
}
