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

// TestMitigationFunnelReconciles verifies the core invariant of the reconciled
// funnel: Allowed + TotalMitigated == HTTPIngress (no clamp when ingress exceeds
// mitigations), and that 5xx errors and XDP packet drops are reported on their
// own axes rather than folded into the request funnel.
func TestMitigationFunnelReconciles(t *testing.T) {
	// Large request baseline so ingress >= mitigations (no clamp).
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

	wantMitigated := f.WAFBlocked + f.RateLimited + f.GeoIPBlocked + f.AuthFailures + f.TurnstileFailures + f.HMACFailures
	if f.TotalMitigated != wantMitigated {
		t.Errorf("total_mitigated = %f, want sum %f", f.TotalMitigated, wantMitigated)
	}

	// The reconciliation invariant.
	if f.Allowed+f.TotalMitigated != f.HTTPIngress {
		t.Errorf("invariant broken: allowed(%f) + mitigated(%f) = %f != ingress(%f)",
			f.Allowed, f.TotalMitigated, f.Allowed+f.TotalMitigated, f.HTTPIngress)
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
	ipBandwidthMu.Lock()
	ipBandwidthMap = make(map[string]*ipBandwidthInternal)
	ipBandwidthMu.Unlock()

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
	ipBandwidthMu.Lock()
	ipBandwidthMap = make(map[string]*ipBandwidthInternal)
	ipBandwidthMu.Unlock()

	// Insert well beyond the cap; the map must stay bounded via eviction.
	for i := 0; i < maxIPBandwidthMapSize*2; i++ {
		RecordIPBandwidth(fmt.Sprintf("10.1.%d.%d", i/256, i%256), 1, 1)
	}

	ipBandwidthMu.RLock()
	n := len(ipBandwidthMap)
	ipBandwidthMu.RUnlock()

	if n > maxIPBandwidthMapSize {
		t.Errorf("ipBandwidthMap size = %d, exceeds cap %d", n, maxIPBandwidthMapSize)
	}
}
