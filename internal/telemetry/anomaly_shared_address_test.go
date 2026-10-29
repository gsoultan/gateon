// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/ebpf"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// throttlingKernel is an attached kernel that records the addresses the
// exploit check rate-limited.
type throttlingKernel struct {
	recordingKernelManager
	limited []string
}

func (m *throttlingKernel) SetAdaptiveRateLimit(ip string, _ time.Duration) error {
	m.limited = append(m.limited, ip)
	return nil
}

func (m *throttlingKernel) GetMapStats() (ebpf.MapStats, error) {
	return ebpf.MapStats{Attached: true}, nil
}

// exploitThreats runs one exploit-scanning check over traffic and returns what
// it recorded, by address.
func exploitThreats(t *testing.T, kernel ebpf.Manager, traffic func(agg *LocalMetricsAggregator)) map[string]SecurityThreat {
	t.Helper()
	_ = ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore(migratedSQLite(t, "anomaly.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = ClosePathStatsStore(context.Background()) })
	ch := ThreatBroadcaster.Subscribe()
	t.Cleanup(func() { ThreatBroadcaster.Unsubscribe(ch) })

	agg := GetAggregator()
	agg.ResetIPStats()
	t.Cleanup(agg.ResetIPStats)
	traffic(agg)

	ad, err := NewAnomalyDetector(&gateonv1.AnomalyDetectionConfig{Enabled: true, Sensitivity: 0.5, EnableExploitDetection: true}, kernel)
	if err != nil {
		t.Fatalf("NewAnomalyDetector: %v", err)
	}
	ad.checkExploitScanning(context.Background(), time.Now())

	threats := make(map[string]SecurityThreat)
	deadline := time.After(10 * time.Second)
	for {
		select {
		case th := <-ch:
			if th.Type == "exploit_scan" {
				threats[th.SourceIP] = th
			}
			if len(threats) == 2 {
				return threats
			}
		case <-deadline:
			return threats
		}
	}
}

// The exploit-scanning check throttled an address in the kernel on its count
// of WAF blocks alone, once past a hundred, whatever share of the address's
// traffic they were. A hundred blocks a minute is one client running a scanner
// behind an office NAT, a campus or a CGNAT pool that sends ten thousand
// requests a minute, and the throttle -- two requests a second, for the whole
// address -- took the other clients offline while the WAF was already
// refusing every attack as it arrived. Root cause: the absolute branch had no
// share bar, while the harm rule everywhere else (harmMinAttackShare) does.
func TestASharedAddressWithAFewAttackersIsNotThrottled(t *testing.T) {
	const shared, scanner = "203.0.113.200", "198.51.100.66"
	kernel := &throttlingKernel{}
	threats := exploitThreats(t, kernel, func(agg *LocalMetricsAggregator) {
		page := httptest.NewRequest(http.MethodGet, "/", nil)
		for range 10000 {
			agg.RecordRequest(shared, http.StatusOK, page)
		}
		for range 150 {
			agg.RecordWAFBlock(shared)
		}
		// A scanner's traffic is mostly attacks, and it is still throttled.
		probe := httptest.NewRequest(http.MethodGet, "/.env", nil)
		for range 30 {
			agg.RecordRequest(scanner, http.StatusForbidden, probe)
			agg.RecordWAFBlock(scanner)
		}
	})

	for _, ip := range kernel.limited {
		if ip == shared {
			t.Fatalf("the shared address was rate-limited in the kernel on 150 blocks in 10,000 requests")
		}
	}
	th, recorded := threats[shared]
	if !recorded {
		t.Fatal("the shared address's blocks were not recorded at all; the operator should still see them")
	}
	if th.ActionTaken != ActionFlagged || th.HeldAgainstSource() {
		t.Fatalf("the shared address's finding was recorded as %q, held against it: %t; want flagged and held against nobody",
			th.ActionTaken, th.HeldAgainstSource())
	}

	if len(kernel.limited) != 1 || kernel.limited[0] != scanner {
		t.Fatalf("kernel limited %v, want the scanner alone", kernel.limited)
	}
	if th := threats[scanner]; th.ActionTaken != ActionThrottled || !th.HeldAgainstSource() {
		t.Fatalf("the scanner was recorded as %q; want throttled and held against it", th.ActionTaken)
	}
}
