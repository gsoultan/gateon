// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build openfinding

package api

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// OPEN, for the owner of applyAutomaticMitigation (out of this review's scope,
// so not changed here): the kernel rate limits it installs on neural_sentinel
// and graph_coordinated_fp findings are invisible to the operator, survive
// "remove mitigation", and ignore the mitigation allowlist that the anomaly
// detector's own throttle honours.
// Run with: go test -tags openfinding -run AutomaticThrottle ./internal/api/

const throttledFinding = "graph_coordinated_fp"

// TestAutomaticThrottleIsReleasedWithTheMitigation: the operator sees a finding,
// decides it was wrong, and removes the mitigation for that address.
func TestAutomaticThrottleIsReleasedWithTheMitigation(t *testing.T) {
	const ip = "10.60.0.1"
	s, rec := throttleTestService(t)
	s.applyAutomaticMitigation(t.Context(), []*gateonv1.Anomaly{{Type: throttledFinding, Score: 85, Source: ip}})
	if rec.throttled([]string{ip}) != 1 {
		t.Fatalf("precondition: the finding did not throttle %s", ip)
	}
	resp, err := s.RemoveMitigatedThreat(t.Context(), &gateonv1.RemoveMitigatedThreatRequest{Source: ip})
	if err != nil {
		t.Fatal(err)
	}
	if rec.cleared[ip] == 0 {
		t.Errorf("remove mitigation for %s answered %q and left its kernel rate limit (one packet per 10ms) in place",
			ip, resp.GetMessage())
	}
}

// TestAutomaticThrottleSparesAllowlistedAddresses: an operator allowlists the
// office egress. telemetry's AnomalyDetector.throttle checks the allowlist
// before installing a limit; applyAutomaticMitigation does not.
func TestAutomaticThrottleSparesAllowlistedAddresses(t *testing.T) {
	const ip = "10.60.0.2"
	mitigation.SetAllowlist([]netip.Prefix{netip.MustParsePrefix(ip + "/32")})
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })
	s, rec := throttleTestService(t)
	s.applyAutomaticMitigation(t.Context(), []*gateonv1.Anomaly{{Type: throttledFinding, Score: 85, Source: ip}})
	if rec.throttled([]string{ip}) != 0 {
		t.Errorf("allowlisted %s was rate-limited in the kernel by an automatic finding", ip)
	}
}

// TestAutomaticThrottleIsVisibleToTheOperator: the mitigation list is where an
// operator looks for what the gateway is doing to an address.
func TestAutomaticThrottleIsVisibleToTheOperator(t *testing.T) {
	const ip = "10.60.0.3"
	s, rec := throttleTestService(t)
	s.applyAutomaticMitigation(t.Context(), []*gateonv1.Anomaly{{Type: throttledFinding, Score: 85, Source: ip}})
	if rec.throttled([]string{ip}) != 1 {
		t.Fatalf("precondition: the finding did not throttle %s", ip)
	}
	telemetry.FlushThreats()
	mitigations, _ := telemetry.GetIPMitigations(t.Context(), 1000, 0)
	for _, m := range mitigations {
		if m.IP == ip {
			return
		}
	}
	t.Errorf("%s is throttled in the kernel and appears nowhere on the mitigation list (%d entries)", ip, len(mitigations))
}

func throttleTestService(t *testing.T) (*ApiService, *recordingLimiter) {
	t.Helper()
	dir := t.TempDir()
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(dir, "throttle.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })
	rec := &recordingLimiter{}
	return NewApiService(ApiServiceConfig{
		Routes:      config.NewRouteRegistry(filepath.Join(dir, "routes.json")),
		Middlewares: config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json")),
		EbpfManager: rec,
	}), rec
}
