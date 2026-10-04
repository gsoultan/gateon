// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package alerting

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestAPlaybookBlocksOnlyASourceTheThreatIsHeldAgainst: a playbook that
// blocks on WAF threats (or on all of them) shunned whoever a threat named --
// the reader of a page whose card number the DLP rules redacted, every client
// an audit-only WAF matched, a client refused for an earlier decision. The
// alert still goes out; the block does not (ADR 0055).
func TestAPlaybookBlocksOnlyASourceTheThreatIsHeldAgainst(t *testing.T) {
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "playbook.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })

	m := &AlertingManager{
		config: &gateonv1.AlertingConfig{
			Enabled: true,
			Playbooks: []*gateonv1.AlertPlaybook{{
				Id: "pb-block", Name: "block WAF threats", EventType: "wafThreat", Action: "block",
			}},
		},
		dispatchers: map[string]Dispatcher{},
		ebpfManager: ebpf.NewHolder(nil),
	}
	gate := identity.IPMitigation()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	serve := func(ip string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = ip + ":40400"
		rr := httptest.NewRecorder()
		gate.ServeHTTP(rr, req)
		return rr.Code
	}

	cases := []struct {
		name   string
		threat telemetry.SecurityThreat
	}{
		{"an audit-only match", telemetry.SecurityThreat{
			Type: "waf_detected", SourceIP: "203.0.113.101", Score: 100, Severity: "critical", Observed: true,
		}},
		{"a data leak in the response it was served", telemetry.SecurityThreat{
			Type: "data_exposure", Category: "waf", SourceIP: "203.0.113.102", Score: 100, Severity: "critical",
			ActionTaken: telemetry.ActionBlocked, Unattributed: true,
		}},
	}
	for _, tc := range cases {
		m.process(&tc.threat)
		if got := serve(tc.threat.SourceIP); got != http.StatusOK {
			t.Errorf("%s: the playbook blocked %s (next request %d); the threat is not held against it",
				tc.name, tc.threat.SourceIP, got)
		}
	}

	// The same playbook still blocks the source of a WAF refusal, so the
	// assertions above are not passing because nothing blocks at all.
	const attacker = "203.0.113.103"
	m.process(&telemetry.SecurityThreat{
		Type: "waf_blocked", SourceIP: attacker, Score: 100, Severity: "high", ActionTaken: telemetry.ActionBlocked,
	})
	if got := serve(attacker); got != http.StatusForbidden {
		t.Fatalf("the playbook did not block the source of a WAF refusal: %d, want 403", got)
	}
}
