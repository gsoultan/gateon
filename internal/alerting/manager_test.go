// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package alerting

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// recordingDispatcher captures what alerting decided to send.
type recordingDispatcher struct {
	mu   sync.Mutex
	sent []telemetry.SecurityThreat
}

func (r *recordingDispatcher) Send(_ context.Context, threat telemetry.SecurityThreat) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, threat)
	return nil
}

func (r *recordingDispatcher) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sent)
}

// waitForCount polls until the dispatcher has seen n alerts or the deadline
// passes. executePlaybook sends on a goroutine, so the assertion cannot be
// immediate -- and a sleep would either be flaky or slow.
func (r *recordingDispatcher) waitForCount(t *testing.T, n int) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r.count() >= n {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return r.count() >= n
}

// stubEbpf is an ebpf.Manager that does nothing. Its presence is the point:
// process only takes the mitigation branch when a manager is configured.
type stubEbpf struct{ shunned []string }

func (s *stubEbpf) Start(context.Context)                            {}
func (s *stubEbpf) ShunIP(ip string) error                           { s.shunned = append(s.shunned, ip); return nil }
func (s *stubEbpf) UnshunIP(string) error                            { return nil }
func (s *stubEbpf) UpdateManagementWhitelist([]string) error         { return nil }
func (s *stubEbpf) SetPortKnockingSequence([]int32) error            { return nil }
func (s *stubEbpf) UpdateLoadBalancerBackends([]string) error        { return nil }
func (s *stubEbpf) SetAdaptiveRateLimit(string, time.Duration) error { return nil }
func (s *stubEbpf) ClearAdaptiveRateLimit(string) error              { return nil }
func (s *stubEbpf) ApplyRLFeedback(string, float64) error            { return nil }
func (s *stubEbpf) SetRLFeedbackHandler(func(string, float64))       {}
func (s *stubEbpf) ShunJA4(string) error                             { return nil }
func (s *stubEbpf) UnshunJA4(string) error                           { return nil }
func (s *stubEbpf) RegisterPhantomPort(uint32) error                 { return nil }
func (s *stubEbpf) UnregisterPhantomPort(uint32) error               { return nil }
func (s *stubEbpf) GetTopIPs(int) ([]ebpf.IPStat, error)             { return nil, nil }
func (s *stubEbpf) GetMapStats() (ebpf.MapStats, error)              { return ebpf.MapStats{}, nil }

// newTestManager builds a manager wired to one dispatcher and one catch-all
// playbook, with eBPF present so the mitigation branch is live.
func newTestManager(em ebpf.Manager) (*AlertingManager, *recordingDispatcher) {
	rec := &recordingDispatcher{}
	return &AlertingManager{
		config: &gateonv1.AlertingConfig{
			Enabled: true,
			Playbooks: []*gateonv1.AlertPlaybook{{
				Id:            "pb",
				EventType:     "all",
				DispatcherIds: []string{"d"},
			}},
		},
		dispatchers: map[string]Dispatcher{"d": rec},
		ebpfManager: em,
	}, rec
}

func TestThreatIsDispatched(t *testing.T) {
	m, rec := newTestManager(&stubEbpf{})

	m.process(&telemetry.SecurityThreat{
		ID: "t1", Type: "sqli", SourceIP: "203.0.113.9", Severity: "high",
	})

	if !rec.waitForCount(t, 1) {
		t.Fatal("a routable threat produced no alert")
	}
}

// TestLoopbackThreatStillAlerts is the bug. The mitigation branch refuses to
// shun loopback -- correctly, since shunning 127.0.0.1 would cut off the
// gateway's own management traffic -- but it did so with a bare `return` out of
// process, which is upstream of the playbook loop. So the threat was never
// dispatched either.
//
// That matters well beyond genuinely local traffic: a gateway behind nginx, a
// Cloudflare tunnel or any sidecar sees 127.0.0.1 as the source for *every*
// request until client-IP extraction is configured. In that deployment the
// dashboard shows alerting enabled, configured and matching, and not one alert
// is ever sent.
func TestLoopbackThreatStillAlerts(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "127.0.0.53"} {
		t.Run(ip, func(t *testing.T) {
			stub := &stubEbpf{}
			m, rec := newTestManager(stub)

			m.process(&telemetry.SecurityThreat{
				ID: "t2", Type: "sqli", SourceIP: ip, Severity: "critical",
			})

			if !rec.waitForCount(t, 1) {
				t.Errorf("a threat from %s produced no alert; refusing to shun "+
					"loopback must not also refuse to report it", ip)
			}
			if len(stub.shunned) != 0 {
				t.Errorf("loopback address %s was shunned (%v); that cuts off the "+
					"gateway's own management traffic", ip, stub.shunned)
			}
		})
	}
}

func TestDisabledConfigDispatchesNothing(t *testing.T) {
	m, rec := newTestManager(&stubEbpf{})
	m.config.Enabled = false

	m.process(&telemetry.SecurityThreat{ID: "t3", Type: "sqli", SourceIP: "203.0.113.9"})

	time.Sleep(50 * time.Millisecond)
	if n := rec.count(); n != 0 {
		t.Errorf("alerting is disabled but %d alerts were sent", n)
	}
}

// TestProcessWithoutEbpfStillAlerts covers the other side of the branch: a
// deployment with eBPF off must still get its alerts.
func TestProcessWithoutEbpfStillAlerts(t *testing.T) {
	m, rec := newTestManager(nil)

	m.process(&telemetry.SecurityThreat{
		ID: "t4", Type: "sqli", SourceIP: "127.0.0.1", Severity: "critical",
	})

	if !rec.waitForCount(t, 1) {
		t.Error("no alert was sent when eBPF is not configured")
	}
}

func TestNilManagerHandleThreatDoesNotPanic(t *testing.T) {
	saved := manager
	manager = nil
	t.Cleanup(func() { manager = saved })

	HandleThreat(&telemetry.SecurityThreat{ID: "t5", SourceIP: "203.0.113.9"})
}

func TestMatchPlaybookEventTypes(t *testing.T) {
	t.Parallel()

	m := &AlertingManager{}
	for _, tc := range []struct {
		name   string
		pb     *gateonv1.AlertPlaybook
		threat telemetry.SecurityThreat
		want   bool
	}{
		{"catch-all matches", &gateonv1.AlertPlaybook{EventType: "all"},
			telemetry.SecurityThreat{Type: "sqli"}, true},
		{"exact type matches", &gateonv1.AlertPlaybook{EventType: "sqli"},
			telemetry.SecurityThreat{Type: "sqli"}, true},
		{"other type does not", &gateonv1.AlertPlaybook{EventType: "xss"},
			telemetry.SecurityThreat{Type: "sqli"}, false},
		{"high_anomaly under threshold", &gateonv1.AlertPlaybook{EventType: "high_anomaly", Threshold: 50},
			telemetry.SecurityThreat{Type: "anomaly", Score: 10}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := m.matchPlaybook(tc.pb, tc.threat); got != tc.want {
				t.Errorf("matchPlaybook = %v, want %v", got, tc.want)
			}
		})
	}
}
