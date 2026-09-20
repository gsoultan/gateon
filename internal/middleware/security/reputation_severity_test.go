// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestReputationBlockRecordsDashboardSeverity: the blocker wrote "HIGH" into
// the threat record. Every consumer compares lower-case — the correlation
// engine ranked it below "low", the SIEM formatter mapped it to informational,
// the dashboard's "critical or high" tile never counted it — so the most widely
// applied refusal in the gateway was invisible to everything that acts on
// severity.
// withState attaches a RequestState the way the chain would.
func withState(req *http.Request, rs *request.RequestState) *http.Request {
	return req.WithContext(request.WithState(req.Context(), rs))
}

func TestReputationBlockRecordsDashboardSeverity(t *testing.T) {
	// A threat only reaches the alerting handler through the store's consumer,
	// so a store is needed; it lives in the test's own directory.
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "rep.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	defer telemetry.ClosePathStatsStore(t.Context())

	captured := make(chan telemetry.SecurityThreat, 4)
	telemetry.SetAlertingHandler(func(th *telemetry.SecurityThreat) {
		select {
		case captured <- *th:
		default:
		}
	})
	defer telemetry.SetAlertingHandler(nil)

	req := withState(httptest.NewRequest(http.MethodGet, "/", nil), &request.RequestState{})
	// A network of its own, so the score this test drives to zero is not the
	// identity any other test's default request resolves to.
	req.RemoteAddr = "198.51.100.77:4321"
	id := telemetry.GetReputationID(req)
	telemetry.DecreaseReputation(id, 100, "test")
	defer telemetry.ResetReputation(id)

	rr := httptest.NewRecorder()
	ReputationBlocker("rep-route")(okOrigin()).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("client at reputation 0: got %d, want 403", rr.Code)
	}

	select {
	case th := <-captured:
		if th.Type != "reputation_block" {
			t.Fatalf("captured a %q threat, want reputation_block", th.Type)
		}
		if th.Severity != kind.SeverityHigh {
			t.Fatalf("reputation block recorded severity %q, want %q", th.Severity, kind.SeverityHigh)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the reputation block never reached the alerting handler")
	}
}
