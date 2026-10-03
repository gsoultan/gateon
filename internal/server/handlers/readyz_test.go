// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/server/readiness"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestReadyzNamesAnEntrypointThatDidNotBind: /readyz looked at the telemetry
// store and nothing else, so a gateway with an entrypoint that never bound
// answered ready. It answers 503 and names the entrypoint and its address.
func TestReadyzNamesAnEntrypointThatDidNotBind(t *testing.T) {
	readiness.ListenerFailed("readyz-websecure", "127.0.0.1:1", errors.New("bind: address already in use"))
	t.Cleanup(func() { readiness.ListenerBound("readyz-websecure", "127.0.0.1:1") })

	mux := http.NewServeMux()
	registerGlobalHandlers(mux, signInAPI{}, &Deps{})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz = %d with an entrypoint that did not bind, want 503", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "readyz-websecure") {
		t.Errorf("/readyz does not name the entrypoint: %s", rr.Body.String())
	}
}

// TestReadyzKeepsADegradedInstanceInRotation: with the configuration database
// unreachable the data plane still serves (ADR 0043 fails block lookups open),
// so /readyz answering 503 would let a load balancer turn a degraded
// single-node gateway into a down one. It answers 200 and names what is wrong.
func TestReadyzKeepsADegradedInstanceInRotation(t *testing.T) {
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "telemetry.db"), 7); err != nil {
		t.Fatalf("InitPathStatsStore: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })
	readiness.CheckDatabase(t.Context(), func(context.Context) error { return errors.New("connection refused") })
	t.Cleanup(func() { readiness.CheckDatabase(context.Background(), func(context.Context) error { return nil }) })

	mux := http.NewServeMux()
	registerGlobalHandlers(mux, signInAPI{}, &Deps{})
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusOK {
		t.Errorf("/readyz = %d with only the configuration database down, want 200: the proxy still serves", rr.Code)
	}
	if body := rr.Body.String(); !strings.Contains(body, "degraded") || !strings.Contains(body, "database") {
		t.Errorf("/readyz does not say what is degraded: %q", body)
	}
}
