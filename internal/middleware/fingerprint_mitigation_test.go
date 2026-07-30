package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

func TestFingerprintMitigationMiddleware(t *testing.T) {
	// Initialize telemetry store
	_ = telemetry.InitPathStatsStore("sqlite::memory:", 1)
	defer telemetry.ClosePathStatsStore(context.Background())

	ja3 := "mitigated-ja3"
	ja4 := "mitigated-ja4"

	// Mitigate JA3
	telemetry.MarkFingerprintMitigated(ja3, "JA3", "Test mitigation", "TestCategory")
	telemetry.MarkFingerprintMitigated(ja4, "JA4", "Test mitigation JA4", "TestCategory")

	mw := FingerprintMitigation()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Blocked JA3", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rs := &request.RequestState{JA3: ja3}
		ctx := context.WithValue(req.Context(), request.RequestStateContextKey{}, rs)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", rr.Code)
		}
	})

	t.Run("Blocked JA4", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rs := &request.RequestState{JA4: ja4}
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
		rs := &request.RequestState{JA3: "clean-ja3"}
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
		telemetry.MarkFingerprintUnmitigated(ja3)

		req := httptest.NewRequest("GET", "/", nil)
		rs := &request.RequestState{JA3: ja3}
		ctx := context.WithValue(req.Context(), request.RequestStateContextKey{}, rs)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200 OK after unmitigation, got %d", rr.Code)
		}
	})
}
