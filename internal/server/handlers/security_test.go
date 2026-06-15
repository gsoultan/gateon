package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/security/fim"
)

func doPostureRequest(t *testing.T, d *Deps) (*httptest.ResponseRecorder, SecurityPostureReport) {
	t.Helper()
	mux := http.NewServeMux()
	registerSecurityHandlers(mux, d)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/security/posture", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var report SecurityPostureReport
	if rec.Code == http.StatusOK {
		if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
			t.Fatalf("decode body: %v", err)
		}
	}
	return rec, report
}

func TestSecurityPostureFallbackWhenNoProvider(t *testing.T) {
	rec, report := doPostureRequest(t, &Deps{Version: "v-test"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if report.Version != "v-test" {
		t.Errorf("version = %q, want v-test", report.Version)
	}
	if report.FIM != nil {
		t.Errorf("FIM should be nil in fallback report, got %+v", report.FIM)
	}
}

func TestSecurityPostureUsesProvider(t *testing.T) {
	fimStatus := &fim.Status{Enabled: true, BaselineFiles: 7, TotalDrift: 2}
	d := &Deps{
		Version: "v-test",
		SecurityPosture: func(context.Context) *SecurityPostureReport {
			return &SecurityPostureReport{
				Version:     "v-test",
				GeneratedAt: time.Now(),
				WAF:         WAFPosture{Enabled: true, AutoUpdate: true},
				ClamAV:      ClamAVPosture{Enabled: true, Installed: true},
				FIM:         fimStatus,
			}
		},
	}

	rec, report := doPostureRequest(t, d)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	tests := []struct {
		name string
		got  bool
		want bool
	}{
		{"waf enabled", report.WAF.Enabled, true},
		{"waf auto-update", report.WAF.AutoUpdate, true},
		{"clamav enabled", report.ClamAV.Enabled, true},
		{"clamav installed", report.ClamAV.Installed, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
			}
		})
	}
	if report.FIM == nil || report.FIM.BaselineFiles != 7 || report.FIM.TotalDrift != 2 {
		t.Errorf("FIM status not propagated: %+v", report.FIM)
	}
}
