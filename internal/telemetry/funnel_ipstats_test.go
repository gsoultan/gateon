// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func gatherIndex(t *testing.T) map[string]*dto.MetricFamily {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	idx := make(map[string]*dto.MetricFamily, len(families))
	for _, f := range families {
		idx[f.GetName()] = f
	}
	return idx
}

// TestMitigationFunnelReconciles verifies the funnel's invariants: ingress is
// the three outcomes, each request once; the stages and OtherRefused add up to
// Refused; and 5xx errors and XDP packet drops are reported on their own axes
// rather than folded into the request funnel.
func TestMitigationFunnelReconciles(t *testing.T) {
	for range 1000 {
		RecordRequestOutcome(true, 200)
	}
	for range 50 {
		RecordRequestOutcome(false, 403)
	}
	RecordRequestOutcome(false, 302)
	RequestsTotal.WithLabelValues("gateon-funnel", "svc", "GET", "200").Add(1000)
	RequestsTotal.WithLabelValues("gateon-funnel", "svc", "GET", "500").Add(7)

	MiddlewareWAFBlockedTotal.WithLabelValues("gateon-funnel", "sqli").Add(11)
	MiddlewareRateLimitRejectedTotal.WithLabelValues("gateon-funnel", "ip").Add(13)
	MiddlewareGeoIPBlockedTotal.WithLabelValues("gateon-funnel", "CN").Add(3)
	MiddlewareAuthFailuresTotal.WithLabelValues("gateon-funnel", "jwt").Add(5)
	MiddlewareHMACFailuresTotal.WithLabelValues("gateon-funnel").Add(2)
	MiddlewareTurnstileTotal.WithLabelValues("gateon-funnel", "fail").Add(4)
	EbpfDroppedPacketsTotal.WithLabelValues("xdp").Add(99)

	f := buildMitigationFunnel(gatherIndex(t))

	if f.HTTPIngress <= 0 {
		t.Fatalf("expected http_ingress > 0, got %f", f.HTTPIngress)
	}
	if f.Allowed+f.Refused+f.Answered != f.HTTPIngress {
		t.Errorf("invariant broken: allowed(%f) + refused(%f) + answered(%f) != ingress(%f)",
			f.Allowed, f.Refused, f.Answered, f.HTTPIngress)
	}

	// Every stage buildMitigationFunnel attributes, not just the six this test
	// seeds. The counters are process-global, so summing only the seeded six
	// made this an assertion about which other tests had run first. If a new
	// stage is added and not here, this fails -- a stage missing from the sum
	// is a refusal counted twice, once by name and once as "other".
	stages := f.WAFBlocked + f.FastPathBlocked + f.RateLimited + f.GeoIPBlocked +
		f.AuthFailures + f.TurnstileFailures + f.HMACFailures +
		f.BotBlocked + f.FileSecurityBlocked + f.DeceptionBlocked +
		f.MitigationBlocked + f.AdvancedSecurityBlock
	if want := max(f.Refused-stages, 0); f.OtherRefused != want {
		t.Errorf("other_refused = %f, want refused(%f) - stages(%f) = %f", f.OtherRefused, f.Refused, stages, want)
	}
	if f.TotalMitigated != f.Refused {
		t.Errorf("total_mitigated = %f, want refused %f", f.TotalMitigated, f.Refused)
	}

	// 5xx and XDP are reported separately, not subtracted into the funnel.
	if f.ServerErrors < 7 {
		t.Errorf("expected server_errors >= 7, got %f", f.ServerErrors)
	}
	if f.XDPPacketsDropped < 99 {
		t.Errorf("expected xdp_packets_dropped >= 99, got %f", f.XDPPacketsDropped)
	}
}

func TestRecordIPBandwidthAccumulates(t *testing.T) {
	resetIPBandwidth()

	RecordIPBandwidth("10.0.0.1", 100, 200)
	RecordIPBandwidth("10.0.0.1", 50, 25)
	RecordIPBandwidth("10.0.0.2", 5, 5)
	RecordIPBandwidth("", 9999, 9999) // empty IP must be ignored

	stats := getIPBandwidthStats()
	byIP := make(map[string]IPMetric, len(stats))
	for _, s := range stats {
		byIP[s.IP] = s
	}

	if _, ok := byIP[""]; ok {
		t.Error("empty IP should not be recorded")
	}
	one := byIP["10.0.0.1"]
	if one.Requests != 2 || one.BytesIn != 150 || one.BytesOut != 225 {
		t.Errorf("10.0.0.1 = %+v, want requests=2 bytesIn=150 bytesOut=225", one)
	}
	if byIP["10.0.0.2"].Requests != 1 {
		t.Errorf("10.0.0.2 requests = %f, want 1", byIP["10.0.0.2"].Requests)
	}
}

func TestRecordIPBandwidthBounded(t *testing.T) {
	resetIPBandwidth()

	// Insert well beyond the cap; the map must stay bounded via eviction.
	// Total capacity is numShards * maxIPBandwidthPerShard = 16 * 64 = 1024.
	maxTotal := numShards * maxIPBandwidthPerShard
	for i := 0; i < maxTotal*2; i++ {
		RecordIPBandwidth(fmt.Sprintf("10.1.%d.%d", i/256, i%256), 1, 1)
	}

	n := len(getIPBandwidthStats())

	if n > maxTotal {
		t.Errorf("ipBandwidth total size = %d, exceeds cap %d", n, maxTotal)
	}
}
