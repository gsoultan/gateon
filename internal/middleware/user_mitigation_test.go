// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

func TestUserMitigationMiddleware(t *testing.T) {
	// Initialize telemetry store
	dbPath := filepath.Join(t.TempDir(), "gateon_mw_user_mit_test.db")

	_ = telemetry.InitPathStatsStore(dbPath, 1)
	defer telemetry.ClosePathStatsStore(context.Background())

	ja4_1 := "mitigated-ja4-1"
	ja4_2 := "mitigated-ja4-2"
	ja4h := "mitigated-ja4h"

	telemetry.MarkUserMitigated(ja4_1, "JA4", "Test mitigation", "TestCategory")
	telemetry.MarkUserMitigated(ja4_2, "JA4", "Test mitigation JA4", "TestCategory")
	telemetry.MarkUserMitigated(ja4_2+"_"+ja4h, "JA4", "Test mitigation JA4+JA4H", "TestCategory")

	mw := UserMitigation()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Blocked JA4 1", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rs := &request.RequestState{JA4Plus: ja4_1}
		ctx := context.WithValue(req.Context(), request.RequestStateContextKey{}, rs)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", rr.Code)
		}
	})

	t.Run("Blocked JA4 Global", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rs := &request.RequestState{JA4Plus: ja4_2}
		ctx := context.WithValue(req.Context(), request.RequestStateContextKey{}, rs)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", rr.Code)
		}
	})

	t.Run("Blocked JA4+JA4H Composite", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rs := &request.RequestState{JA4Plus: ja4_2 + "_" + ja4h}
		ctx := context.WithValue(req.Context(), request.RequestStateContextKey{}, rs)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", rr.Code)
		}
	})

	t.Run("Allowed Clean Fingerprint", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rs := &request.RequestState{JA4: "clean-ja4"}
		ctx := context.WithValue(req.Context(), request.RequestStateContextKey{}, rs)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("Immediate Effect of Unmitigation", func(t *testing.T) {
		// Unmitigate
		telemetry.MarkUserUnmitigated(ja4_1)

		req := httptest.NewRequest("GET", "/", nil)
		rs := &request.RequestState{JA4Plus: ja4_1}
		ctx := context.WithValue(req.Context(), request.RequestStateContextKey{}, rs)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200 OK after unmitigation, got %d", rr.Code)
		}
	})
}

func TestIPMitigationMiddleware(t *testing.T) {
	// Initialize telemetry store
	dbPath := filepath.Join(t.TempDir(), "gateon_mw_ip_mit_test.db")

	_ = telemetry.InitPathStatsStore(dbPath, 1)
	defer telemetry.ClosePathStatsStore(context.Background())

	ip := "1.2.3.4"
	telemetry.MarkIPMitigated(ip, "Test mitigation")

	mw := IPMitigation()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Blocked IP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = ip + ":12345"

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", rr.Code)
		}
	})

	t.Run("Allowed IP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "5.6.7.8:12345"

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", rr.Code)
		}
	})

	t.Run("Immediate Effect of Unmitigation", func(t *testing.T) {
		telemetry.MarkIPUnmitigated(ip)

		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = ip + ":12345"

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200 OK after unmitigation, got %d", rr.Code)
		}
	})
}
