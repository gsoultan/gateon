// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/ai"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The diagnostics loop throttled, in the kernel, every address a
// neural_sentinel or graph_coordinated_fp finding scored above 80: at once, on
// one finding, to 100 packets a second. That path is gone. Findings now go to
// the RL limiter, which limits an address only after findings on repeated
// passes, renews the limit while they continue and lets it lapse when they
// stop. These are the properties the old path had to be fixed for -- a release
// lifts the limit, the allowlist is never limited -- held on the new one, and
// the one it never had: a finding is not a verdict.

// TestASingleFindingNeverThrottles: one pass, one finding scoring 95.
func TestASingleFindingNeverThrottles(t *testing.T) {
	const ip = "10.60.0.4"
	s, rec := throttleTestService(t)
	s.throttleRepeatedFindings([]*gateonv1.Anomaly{neuralFinding(ip, 95)})
	if rec.throttled([]string{ip}) != 0 {
		t.Errorf("one neural_sentinel finding rate-limited %s in the kernel", ip)
	}
}

// TestRepeatedFindingsThrottle: the same finding on three passes is.
func TestRepeatedFindingsThrottle(t *testing.T) {
	const ip = "10.60.0.5"
	s, rec := throttleTestService(t)
	runPasses(s, 3, neuralFinding(ip, 95))
	if rec.throttled([]string{ip}) != 1 {
		t.Fatalf("findings on three passes did not rate-limit %s", ip)
	}
}

// TestOnePassCountsOnceHoweverManyFindings: the Neural Sentinel and Graph
// Intelligence both naming an address in one pass is one piece of evidence
// seen twice, not repetition.
func TestOnePassCountsOnceHoweverManyFindings(t *testing.T) {
	const ip = "10.60.0.6"
	s, rec := throttleTestService(t)
	cluster := &gateonv1.Anomaly{Type: graphCoordinatedType, Score: 100, SourceIps: []string{ip, "10.60.1.1"}}
	runPasses(s, 2, neuralFinding(ip, 95), cluster, cluster, neuralFinding(ip, 99))
	if rec.throttled([]string{ip}) != 0 {
		t.Errorf("four findings in each of two passes rate-limited %s", ip)
	}
}

// TestAGraphFindingThrottlesEveryMember: a cluster's addresses are each
// limited once the cluster has been found on repeated passes.
func TestAGraphFindingThrottlesEveryMember(t *testing.T) {
	members := []string{"10.60.2.1", "10.60.2.2", "10.60.2.3", "10.60.2.4", "10.60.2.5"}
	s, rec := throttleTestService(t)
	runPasses(s, 3, &gateonv1.Anomaly{Type: graphCoordinatedType, Score: 100, SourceIps: members})
	if n := rec.throttled(members); n != len(members) {
		t.Errorf("%d of the cluster's %d addresses were rate-limited", n, len(members))
	}
}

// TestAutomaticThrottleIsReleasedWithTheMitigation: the operator sees a finding,
// decides it was wrong, and removes the mitigation for that address. The limit
// goes -- and so does the history, or the next pass would set it again.
func TestAutomaticThrottleIsReleasedWithTheMitigation(t *testing.T) {
	const ip = "10.60.0.1"
	s, rec := throttleTestService(t)
	runPasses(s, 3, neuralFinding(ip, 95))
	if rec.throttled([]string{ip}) != 1 {
		t.Fatalf("precondition: the findings did not throttle %s", ip)
	}
	resp, err := s.RemoveMitigatedThreat(t.Context(), &gateonv1.RemoveMitigatedThreatRequest{Source: ip})
	if err != nil {
		t.Fatal(err)
	}
	if rec.throttled([]string{ip}) != 0 {
		t.Fatalf("remove mitigation for %s answered %q and left its kernel rate limit in place", ip, resp.GetMessage())
	}
	runPasses(s, 1, neuralFinding(ip, 95))
	if rec.throttled([]string{ip}) != 0 {
		t.Errorf("%s was rate-limited again by the first analysis pass after its release", ip)
	}
}

// TestAutomaticThrottleSparesAllowlistedAddresses: an operator allowlists the
// office egress; no number of findings limits it.
func TestAutomaticThrottleSparesAllowlistedAddresses(t *testing.T) {
	const ip = "10.60.0.2"
	mitigation.SetAllowlist([]netip.Prefix{netip.MustParsePrefix(ip + "/32")})
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })
	s, rec := throttleTestService(t)
	runPasses(s, 10, neuralFinding(ip, 99))
	if rec.throttled([]string{ip}) != 0 {
		t.Errorf("allowlisted %s was rate-limited in the kernel by automatic findings", ip)
	}
}

// TestBenignPopulationsAreNeverThrottled runs the detectors and the closed
// loop, pass after pass, over clients an operator would never want limited:
// forty people browsing, a dashboard polling every 5s, a health checker, a CI
// runner, an office's egress carrying fifty users, a tab polling into 401s
// after its session expired, and five visitors on one browser build. At the
// most sensitive setting, nothing is rate-limited.
func TestBenignPopulationsAreNeverThrottled(t *testing.T) {
	freshGraph(t)
	s, rec := throttleTestService(t)
	tf := newTraffic(41, time.Now().Add(-10*time.Minute))
	tf.browsers("10.50", 40)
	tf.poller("10.52.0.1", "/api/status", 5*time.Second, 120)
	tf.poller("10.52.0.2", "/healthz", 10*time.Second, 60)
	tf.ciRunner("10.52.0.3")
	tf.natEgress("10.52.0.4")
	tf.expiredSessionPoller("10.52.0.5", "/api/status", 5*time.Second, 120)
	class := "t13d1516h2_8daaf6152771_" + t.Name()
	for v := range 5 {
		tf.classVisitor(fmt.Sprintf("10.54.0.%d", v+1), class, time.Now().Add(-2*time.Minute))
	}
	for range 10 {
		s.throttleRepeatedFindings(neuralEngine(sensitivityHighest).Analyze(t.Context(), tf.data()))
	}
	if len(rec.limitedAddresses()) != 0 {
		t.Errorf("benign clients were rate-limited in the kernel: %v", rec.limitedAddresses())
	}
}

// TestAttacksAreThrottled runs the same loop over a scanner, a credential
// stuffer and a five-address campaign among forty people browsing, at the
// default setting. By the fifth pass every attacker is limited, and no one else.
func TestAttacksAreThrottled(t *testing.T) {
	freshGraph(t)
	s, rec := throttleTestService(t)
	now := time.Now()
	tf := newTraffic(42, now.Add(-10*time.Minute))
	tf.browsers("10.50", 40)
	tf.scanner("10.55.0.1", 200, 10)
	tf.credentialStuffer("10.55.0.2", 100)
	attackers := []string{"10.55.0.1", "10.55.0.2"}
	for v := range 5 {
		ip := fmt.Sprintf("10.56.0.%d", v+1)
		attackers = append(attackers, ip)
		tf.classAttacker(ip, "t13d0000h1_555555555555_"+t.Name(), 3, now.Add(-time.Minute))
	}
	for range 5 {
		data := tf.data()
		data.Now = now
		s.throttleRepeatedFindings(neuralEngine(sensitivityDefault).Analyze(t.Context(), data))
	}
	if n := rec.throttled(attackers); n != len(attackers) {
		t.Errorf("%d of %d attackers were rate-limited; limited: %v", n, len(attackers), rec.limitedAddresses())
	}
	if got := len(rec.limitedAddresses()); got != len(attackers) {
		t.Errorf("%d addresses were limited, want only the %d attackers: %v", got, len(attackers), rec.limitedAddresses())
	}
}

// neuralFinding is a Neural Sentinel finding against ip at score (0..100).
func neuralFinding(ip string, score float64) *gateonv1.Anomaly {
	return &gateonv1.Anomaly{Type: neuralSentinelType, Score: score, Source: ip}
}

// runPasses reports findings to the closed loop on n analysis passes.
func runPasses(s *ApiService, n int, findings ...*gateonv1.Anomaly) {
	for range n {
		s.throttleRepeatedFindings(findings)
	}
}

// throttleTestService is an ApiService wired as production wires it: the RL
// limiter setting leased limits through an eBPF holder, over a manager that
// records what reaches the kernel.
func throttleTestService(t *testing.T) (*ApiService, *recordingLimiter) {
	t.Helper()
	dir := t.TempDir()
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(dir, "throttle.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })
	rec := &recordingLimiter{}
	holder := ebpf.NewHolder(rec)
	return NewApiService(ApiServiceConfig{
		Routes:      config.NewRouteRegistry(filepath.Join(dir, "routes.json")),
		Middlewares: config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json")),
		EbpfManager: holder,
		Throttles:   ai.NewReinforcementLearningLimiter(holder),
	}), rec
}
