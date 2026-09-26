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

// TestPlaybookBlockIsEnforced is the regression test for a playbook action that
// logged a block it had not applied.
//
// "Block IP (XDP Shun)" called the eBPF manager's ShunIP and nothing else. The
// manager alerting is given is the eBPF Holder, whose ShunIP answers nil when
// eBPF is disabled -- the default, and the only possibility off Linux -- so the
// playbook logged "playbook automatically shunned IP" and the source carried on.
// Even with eBPF running the shun was recorded nowhere: not on the mitigation
// list, not where the request path's IP block looks, and gone on restart.
func TestPlaybookBlockIsEnforced(t *testing.T) {
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "playbook.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })

	const ip = "203.0.113.91"
	m := &AlertingManager{
		config: &gateonv1.AlertingConfig{
			Enabled: true,
			Playbooks: []*gateonv1.AlertPlaybook{{
				Id: "pb-block", Name: "block attackers", EventType: "all", Action: "block",
			}},
		},
		dispatchers: map[string]Dispatcher{},
		ebpfManager: ebpf.NewHolder(nil), // what main hands alerting, with eBPF disabled
	}

	gate := identity.IPMitigation()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	serve := func() int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = ip + ":40400"
		rr := httptest.NewRecorder()
		gate.ServeHTTP(rr, req)
		return rr.Code
	}
	if got := serve(); got != http.StatusOK {
		t.Fatalf("setup: %s was refused before any playbook ran: %d", ip, got)
	}

	m.process(&telemetry.SecurityThreat{
		ID: "pb-t1", Type: "waf_blocked", SourceIP: ip, Score: 100,
		Severity: "high", ActionTaken: telemetry.ActionBlocked,
	})

	if got := serve(); got != http.StatusForbidden {
		t.Fatalf("a playbook with the block action matched a threat from %s, and the next "+
			"request from it got %d, want 403", ip, got)
	}
}
