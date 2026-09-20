// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestRecognitionMiddlewaresRecordDashboardSeverity is the second half of the
// bug TestReputationBlockRecordsDashboardSeverity documents, found while
// splitting this package and still live until now.
//
// The reputation blocker was fixed when it was caught writing "HIGH"; the
// three recognition middlewares were writing "CRITICAL", "HIGH" and "MEDIUM"
// the whole time and nobody went back for them. Every consumer compares
// lower-case: severityRank in the correlation engine lowercases before it
// switches, the SIEM formatter maps anything unrecognised to informational,
// and the dashboard's "critical or high" tile counts exact matches. So an XSS
// or SQLi detection -- scored 50 and 60, "CRITICAL" by its own record --
// ranked below a "low" and was counted by nothing.
//
// The assertion is deliberately about case rather than about a specific
// string: what makes this bug expensive is that it is silent, and a severity
// the pipeline does not recognise is silent by construction.
func TestRecognitionMiddlewaresRecordDashboardSeverity(t *testing.T) {
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "rec.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	defer telemetry.ClosePathStatsStore(t.Context())

	recorded := make(chan telemetry.SecurityThreat, 8)
	telemetry.SetAlertingHandler(func(th *telemetry.SecurityThreat) {
		select {
		case recorded <- *th:
		default:
		}
	})
	defer telemetry.SetAlertingHandler(nil)

	known := map[string]bool{
		kind.SeverityCritical: true,
		kind.SeverityHigh:     true,
		kind.SeverityMedium:   true,
		kind.SeverityLow:      true,
	}

	cases := []struct {
		name  string
		mw    kind.Middleware
		query string
	}{
		{"xss", XSSRecognition("sev-xss"), "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"},
		{"sqli", SQLiRecognition("sev-sqli"), "id=1%20UNION%20SELECT%20password%20FROM%20users"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			drain(recorded)

			h := tc.mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodGet, "http://example.com/?"+tc.query, nil)
			req.RemoteAddr = "203.0.113.31:5555"
			h.ServeHTTP(httptest.NewRecorder(), req)

			threat := await(t, recorded)
			if threat.Severity == "" {
				t.Fatal("threat recorded with no severity at all")
			}
			if !known[threat.Severity] {
				t.Errorf("severity %q is not one the pipeline recognises; "+
					"severityRank lowercases before matching, so this detection "+
					"ranks below \"low\" and the dashboard's critical-or-high "+
					"tile never counts it", threat.Severity)
			}
			if threat.Severity != strings.ToLower(threat.Severity) {
				t.Errorf("severity %q is upper-case; every consumer compares "+
					"lower-case", threat.Severity)
			}
		})
	}
}

func drain(ch chan telemetry.SecurityThreat) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func await(t *testing.T, ch chan telemetry.SecurityThreat) telemetry.SecurityThreat {
	t.Helper()
	select {
	case threat := <-ch:
		return threat
	case <-time.After(5 * time.Second):
		t.Fatal("no threat recorded; the middleware did not detect the payload")
		return telemetry.SecurityThreat{}
	}
}
