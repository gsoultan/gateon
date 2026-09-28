// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/rules/op"
	"github.com/gsoultan/gwaf/types"
)

func TestWAF_AuditLogAndBodyLimits(t *testing.T) {
	// Minimal WAF with body limit and custom rule
	mw, err := WAF(WAFConfig{
		RequestBodyLimit: 10, // Very small limit
		ExtraRules: rules.Set{{
			ID:       1000001,
			Phase:    types.PhaseRequestBody,
			Targets:  []types.Target{{Kind: types.TargetArgs}},
			Op:       op.Contains("blockme"),
			Actions:  []rules.Action{rules.BlockWithStatus(403)},
			Severity: types.SeverityCritical, Confidence: types.Certain,
			Msg: "test rule",
		}},
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 1. Check body limit
	req := httptest.NewRequest("POST", "/", strings.NewReader("this is a very long body that should be blocked"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden && rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("body limit: expected error code (403/413), got %d", rr.Code)
	}

	// 2. Check rule match
	req = httptest.NewRequest("GET", "/?test=blockme", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("rule match: expected 403, got %d", rr.Code)
	}
}

type mockEbpfManager struct {
	shunnedIP string
	mu        sync.RWMutex
}

func (m *mockEbpfManager) ShunIP(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shunnedIP = ip
	return nil
}

func (m *mockEbpfManager) getShunnedIP() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.shunnedIP
}
func (m *mockEbpfManager) UnshunIP(ip string) error                                     { return nil }
func (m *mockEbpfManager) UpdateManagementWhitelist(ips []string) error                 { return nil }
func (m *mockEbpfManager) SetPortKnockingSequence(seq []int32) error                    { return nil }
func (m *mockEbpfManager) Start(ctx context.Context)                                    {}
func (m *mockEbpfManager) UpdateLoadBalancerBackends(ips []string) error                { return nil }
func (m *mockEbpfManager) SetAdaptiveRateLimit(ip string, interval time.Duration) error { return nil }
func (m *mockEbpfManager) ClearAdaptiveRateLimit(ip string) error                       { return nil }
func (m *mockEbpfManager) GetTopIPs(limit int) ([]ebpf.IPStat, error)                   { return nil, nil }
func (m *mockEbpfManager) GetMapStats() (ebpf.MapStats, error)                          { return ebpf.MapStats{}, nil }

type telemetryMockWrapper struct {
	*mockEbpfManager
}

func (w *telemetryMockWrapper) GetTopIPs(limit int) ([]ebpf.IPStat, error) { return nil, nil }

// ShunIPUntil is how an automatic shun reaches the kernel: leased to lapse
// with it (ADR 0031), as the eBPF Holder does. A shun with no future end is
// not recorded, so the test also proves the lease is a real one.
func (w *telemetryMockWrapper) ShunIPUntil(ip string, until time.Time) error {
	if !until.After(time.Now()) {
		return nil
	}
	return w.ShunIP(ip)
}

func TestWAF_Shunning(t *testing.T) {
	// Initialize telemetry store for escalation logic
	dbPath := filepath.Join(t.TempDir(), "gateon_shun_test.db")

	if err := telemetry.InitPathStatsStore(dbPath, 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	defer telemetry.ClosePathStatsStore(context.Background())

	mockEbpf := &mockEbpfManager{}
	// Note: In the new architecture, WAF doesn't call EbpfManager directly.
	// It calls telemetry.RecordSecurityThreat, which triggers escalation.
	// We need to set the global eBPF manager for telemetry to use.
	telemetry.SetEbpfManager(&telemetryMockWrapper{mockEbpf})

	mw, err := WAF(WAFConfig{
		EbpfManager: mockEbpf,
		ExtraRules: rules.Set{{
			ID:       1000002,
			Phase:    types.PhaseRequestBody,
			Targets:  []types.Target{{Kind: types.TargetArgs}},
			Op:       op.Contains("shunme"),
			Actions:  []rules.Action{rules.BlockWithStatus(403)},
			Severity: types.SeverityCritical, Confidence: types.Certain,
			Msg: "shun test rule",
		}},
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// An address no other test uses: the evidence towards a shun is kept per
	// address, across tests.
	const ip = "198.51.100.223"
	attack := func(build int) {
		req := httptest.NewRequest("GET", "/?test=shunme", nil)
		req.RemoteAddr = ip + ":1234"
		ja4plus := "user-" + string(rune('0'+build)) + "_ge11nn0200_90c635b248af"
		rs := &request.RequestState{JA4Plus: ja4plus}
		req = req.WithContext(context.WithValue(req.Context(), request.RequestStateContextKey{}, rs))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("build %d: expected 403, got %d", build, rr.Code)
		}
	}

	// Threats are processed off the request path; FlushThreats waits for the
	// store to finish them, escalation included. Checking without it raced the
	// store, and passed only while there were few threats to process.
	//
	// Five client builds refused by the WAF is the bar ADR 0029 sets for
	// shunning an address. Four is an office with a few infected machines: each
	// build is refused on its own, and the address stays up.
	for build := 1; build <= 4; build++ {
		attack(build)
	}
	telemetry.FlushThreats()
	if got := mockEbpf.getShunnedIP(); got != "" {
		t.Fatalf("%s was shunned after 4 attacking builds; the bar is 5", got)
	}
	attack(5)
	telemetry.FlushThreats()
	if got := mockEbpf.getShunnedIP(); got != ip {
		t.Errorf("expected %s to be shunned after 5 attacking builds, got %q", ip, got)
	}
}
