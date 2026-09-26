// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestAnomalyShunIsEnforced is the regression test for a detector that
// recorded a shun it had not applied.
//
// On a brute-force rate above 0.8, or a WAF-block pattern past its critical
// threshold, the anomaly detector called the eBPF manager's ShunIP, discarded
// the error, and recorded the threat as "shunned" -- which the store counts as
// mitigated, the Security Hub shows as blocked and the dashboard's mitigated
// tile adds up. But the detector is handed the eBPF Holder, whose ShunIP
// answers nil when eBPF is disabled (the default, and the only possibility off
// Linux), and the manager's own ShunIP fails when the program is not loaded.
// Either way nothing refused the source: the kernel map was never written, and
// the address was not recorded where the request path's IP block looks.
//
// The detector runs for real, on the eBPF holder main gives it, and the claim
// it records is checked against the middleware every entrypoint carries.
func TestAnomalyShunIsEnforced(t *testing.T) {
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "anomaly.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })

	cases := []struct {
		name, ip, threatType string
		cfg                  *gateonv1.AnomalyDetectionConfig
		traffic              func(agg *telemetry.LocalMetricsAggregator, ip string)
	}{
		{
			name: "brute force", ip: "203.0.113.81", threatType: "brute_force_attempt",
			cfg: &gateonv1.AnomalyDetectionConfig{Sensitivity: 0.5, EnableBruteForceDetection: true},
			traffic: func(agg *telemetry.LocalMetricsAggregator, ip string) {
				for range 20 {
					agg.RecordRequest(ip, http.StatusUnauthorized)
				}
			},
		},
		{
			name: "exploit scanning", ip: "203.0.113.82", threatType: "exploit_scan",
			cfg: &gateonv1.AnomalyDetectionConfig{Sensitivity: 1, EnableExploitDetection: true},
			traffic: func(agg *telemetry.LocalMetricsAggregator, ip string) {
				for range 30 {
					agg.RecordRequest(ip, http.StatusForbidden)
					agg.RecordWAFBlock(ip)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.Enabled = true
			tc.cfg.CheckIntervalSeconds = 1
			th := runDetectorUntil(t, tc.cfg, tc.threatType, tc.ip, func() {
				tc.traffic(telemetry.GetAggregator(), tc.ip)
			})
			t.Cleanup(func() { _ = telemetry.MarkIPUnmitigated(tc.ip) })

			if th.ActionTaken != telemetry.ActionShunned {
				t.Fatalf("the detector recorded %q; a critical %s is documented to shun", th.ActionTaken, tc.threatType)
			}
			if got := serveFromIP(tc.ip); got != http.StatusForbidden {
				t.Fatalf("the detector recorded %s as shunned, and the next request from it got %d, want 403",
					tc.ip, got)
			}
		})
	}
}

// TestAnomalyThrottleIsNotClaimedWithoutAKernel is the same defect on the
// milder branch: below the shun threshold the detector installs an adaptive
// kernel rate limit, and it recorded "throttled" after discarding the result.
// Only an attached eBPF program can throttle, and the Holder answers nil when
// there is none, so a gateway without one reported throttling it never did.
func TestAnomalyThrottleIsNotClaimedWithoutAKernel(t *testing.T) {
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "throttle.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })

	const ip = "203.0.113.83"
	cfg := &gateonv1.AnomalyDetectionConfig{
		Enabled: true, CheckIntervalSeconds: 1, Sensitivity: 0.5, EnableBruteForceDetection: true,
	}
	// 16 of 20 failing: above the detection rate, not above the shun rate.
	th := runDetectorUntil(t, cfg, "brute_force_attempt", ip, func() {
		agg := telemetry.GetAggregator()
		for i := range 20 {
			status := http.StatusOK
			if i < 16 {
				status = http.StatusUnauthorized
			}
			agg.RecordRequest(ip, status)
		}
	})
	if th.ActionTaken == telemetry.ActionThrottled {
		t.Fatalf("recorded %q with no eBPF program attached to throttle anything", th.ActionTaken)
	}
}

// runDetectorUntil starts the detector on the production eBPF holder with
// nothing installed in it -- eBPF disabled, the default -- and returns the first
// threat of the given type from the given address.
func runDetectorUntil(t *testing.T, cfg *gateonv1.AnomalyDetectionConfig, threatType, ip string, traffic func()) telemetry.SecurityThreat {
	t.Helper()
	ch := telemetry.ThreatBroadcaster.Subscribe()
	t.Cleanup(func() { telemetry.ThreatBroadcaster.Unsubscribe(ch) })

	det, err := telemetry.NewAnomalyDetector(cfg, ebpf.NewHolder(nil))
	if err != nil {
		t.Fatalf("NewAnomalyDetector: %v", err)
	}
	traffic()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); det.Start(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	deadline := time.After(15 * time.Second)
	for {
		select {
		case th := <-ch:
			if th.Type == threatType && th.SourceIP == ip {
				return th
			}
		case <-deadline:
			t.Fatalf("the detector never reported a %s from %s", threatType, ip)
		}
	}
}

// serveFromIP sends a request from ip through the IP-mitigation middleware.
func serveFromIP(ip string) int {
	gate := identity.IPMitigation()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ip + ":40300"
	rr := httptest.NewRecorder()
	gate.ServeHTTP(rr, req)
	return rr.Code
}
