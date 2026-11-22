// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gateon/internal/security/waf/advisory"
	"github.com/gsoultan/gateon/internal/telemetry"
)

const advisedInjection = "/shop/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--"

// advisor makes worker the gateway's advisory worker for the test, in mode,
// and returns the queue. The queue sends one sample a batch, so a test waits
// on nothing but the worker.
func advisor(t *testing.T, worker http.Handler, mode advisory.Mode) *advisory.Queue {
	t.Helper()
	srv := httptest.NewServer(worker)
	t.Cleanup(srv.Close)
	q, err := advisory.New(advisory.Config{
		URL: srv.URL, Token: "worker-token", Mode: mode, Capacity: 16, BatchSize: 1, Backoff: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new queue: %v", err)
	}
	shared := advisory.Shared
	advisory.Shared = func() *advisory.Queue { return q }
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { q.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		<-done
		advisory.Shared = shared
	})
	return q
}

// recording answers nothing and passes on each sample it is asked about.
func recording(asked chan<- advisory.Sample) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Samples []advisory.Sample `json:"samples"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		_, _ = w.Write([]byte(`{"verdicts":[]}`))
		for _, s := range b.Samples {
			asked <- s
		}
	}
}

// advisedRoute is a route WAF built from cfg, in front of an origin that
// rewrites the request as a proxy does.
func advisedRoute(t *testing.T, route string, cfg map[string]string) http.Handler {
	t.Helper()
	d, dialect, err := db.Open("sqlite::memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Migrate(d, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := waf.NewStore(d)
	if err := store.Seed(t.Context()); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	wafCfg := parseWAFConfig(cfg)
	wafCfg.WafRules = store
	wafCfg.RouteID = route
	mw, err := WAF(wafCfg)
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "/internal/rewritten"
		r.Header.Set("X-Added-By-The-Proxy", "1")
		_, _ = w.Write([]byte("ok"))
	}))
}

func from(client string, r *http.Request) *http.Request {
	r.RemoteAddr = client + ":40000"
	return r
}

func awaitSample(t *testing.T, asked <-chan advisory.Sample) advisory.Sample {
	t.Helper()
	select {
	case s := <-asked:
		return s
	case <-time.After(10 * time.Second):
		t.Fatal("the worker was not asked")
		panic("unreachable")
	}
}

// A route that asks offers what its rules matched and let through, and one
// in its sample rate of the rest. What the WAF refused is not a question.
func TestAdvisory_OffersWhatWasForwardedAndIsWorthAsking(t *testing.T) {
	asked := make(chan advisory.Sample, 8)
	q := advisor(t, recording(asked), advisory.Record)

	// Audit only: the injection matches, and is forwarded.
	audit := advisedRoute(t, "advise-audit", map[string]string{keyAdvisoryReview: "true", "audit_only": "true"})
	audit.ServeHTTP(httptest.NewRecorder(), from("203.0.113.9", sampleGet(advisedInjection)))
	s := awaitSample(t, asked)
	if s.Why != advisory.WhyMatched || len(s.Rules) == 0 || s.Target != "/shop/search" {
		t.Errorf("sample %+v of %+v", s, s.Entry)
	}
	if _, rewritten := s.Headers["X-Added-By-The-Proxy"]; rewritten {
		t.Error("the sample is of the request after the proxy rewrote it")
	}
	// Nothing matched this one and the route samples none.
	audit.ServeHTTP(httptest.NewRecorder(), from("203.0.113.9", sampleGet("/shop/items?page=2")))
	if got := q.Status().Offered; got != 1 {
		t.Errorf("offered %d after an ordinary request on a route that samples none", got)
	}

	// Enforcing: the injection is refused, and so not offered.
	enforcing := advisedRoute(t, "advise-enforce", map[string]string{keyAdvisoryReview: "true", keyAdvisorySampleRate: "1"})
	rec := httptest.NewRecorder()
	enforcing.ServeHTTP(rec, from("203.0.113.9", sampleGet(advisedInjection)))
	if rec.Code != http.StatusForbidden || q.Status().Offered != 1 {
		t.Errorf("status %d, offered %d after a refused request", rec.Code, q.Status().Offered)
	}
	// The ordinary one is, at one in one.
	enforcing.ServeHTTP(httptest.NewRecorder(), from("203.0.113.9", sampleGet("/shop/items?page=2")))
	if s := awaitSample(t, asked); s.Why != advisory.WhySampled || s.Target != "/shop/items" {
		t.Errorf("sample %+v of %+v", s, s.Entry)
	}
}

// Off is the default: a route that does not ask sends nothing, whatever the
// gateway has configured.
func TestAdvisory_OffByDefault(t *testing.T) {
	q := advisor(t, recording(make(chan advisory.Sample, 8)), advisory.Record)
	for name, cfg := range map[string]map[string]string{
		"advise-default": {"audit_only": "true"},
		"advise-false":   {keyAdvisoryReview: "false", keyAdvisorySampleRate: "1", "audit_only": "true"},
	} {
		h := advisedRoute(t, name, cfg)
		h.ServeHTTP(httptest.NewRecorder(), from("203.0.113.9", sampleGet(advisedInjection)))
		h.ServeHTTP(httptest.NewRecorder(), from("203.0.113.9", sampleGet("/shop/items?page=2")))
	}
	if got := q.Status().Offered; got != 0 {
		t.Errorf("routes that do not ask offered %d samples", got)
	}
}

// A route that asks on a gateway with no worker runs as any other.
func TestAdvisory_ARouteThatAsksWithNoWorkerStillServes(t *testing.T) {
	shared := advisory.Shared
	advisory.Shared = advisory.Off
	t.Cleanup(func() { advisory.Shared = shared })
	if advisorFor(WAFConfig{AdvisoryReview: true}) != nil {
		t.Fatal("a gateway with no worker has an advisor")
	}
	h := advisedRoute(t, "advise-no-worker", map[string]string{keyAdvisoryReview: "true", keyAdvisorySampleRate: "1"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, from("203.0.113.9", sampleGet("/shop/items?page=2")))
	if rec.Code != http.StatusOK {
		t.Errorf("status %d", rec.Code)
	}
}

func advisoryThreats(t *testing.T) chan telemetry.SecurityThreat {
	t.Helper()
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "advisory.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })
	threats := telemetry.ThreatBroadcaster.Subscribe()
	t.Cleanup(func() { telemetry.ThreatBroadcaster.Unsubscribe(threats) })
	return threats
}

func awaitAdvisoryThreat(t *testing.T, threats <-chan telemetry.SecurityThreat) telemetry.SecurityThreat {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case th := <-threats:
			if th.Type == telemetry.ThreatWAFAdvisory {
				return th
			}
		case <-deadline:
			t.Fatal("no advisory threat was recorded")
		}
	}
}

// The whole of it, with the reference worker: a route whose SQL injection
// rules are switched off forwards an injection, the worker says so after the
// fact, and the Security Hub gets an entry about the client the worker was
// never told of. In record mode the entry is held against nobody.
func TestAdvisory_AForwardedAttackIsFlaggedAfterTheFactAgainstItsClient(t *testing.T) {
	threats := advisoryThreats(t)
	worker, err := advisory.NewWorker("worker-token", 4)
	if err != nil {
		t.Fatalf("new worker: %v", err)
	}
	advisor(t, worker, advisory.Record)

	h := advisedRoute(t, "advise-tuned-away", map[string]string{
		keyAdvisoryReview: "true", keyAdvisorySampleRate: "1", "sqli": "false",
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, from("203.0.113.9", sampleGet(advisedInjection+"&api_key=the-clients-key")))
	if rec.Code != http.StatusOK {
		t.Fatalf("the route refused what its switches say it forwards: %d", rec.Code)
	}

	th := awaitAdvisoryThreat(t, threats)
	if th.SourceIP != "203.0.113.9" || th.RouteID != "advise-tuned-away" || th.Method != http.MethodGet {
		t.Errorf("recorded against %q on %q (%s)", th.SourceIP, th.RouteID, th.Method)
	}
	if !th.Observed || th.HeldAgainstSource() || th.Mitigated {
		t.Errorf("a record-mode verdict is held against its source: %+v", th)
	}
	if !strings.Contains(th.Details, "rule ") || !strings.HasPrefix(th.RequestURI, "/shop/search") {
		t.Errorf("details %q, uri %q", th.Details, th.RequestURI)
	}
	if strings.Contains(th.RequestURI, "the-clients-key") {
		t.Errorf("the recorded URI carries a credential: %s", th.RequestURI)
	}
}

// In reputation mode a verdict is evidence, and never enough of it on its
// own for the gateway to act on one.
func TestAdvisory_ReputationModeHoldsACappedVerdictAgainstTheSource(t *testing.T) {
	threats := advisoryThreats(t)
	entry := advisedSample(t)
	for mode, held := range map[advisory.Mode]bool{advisory.Record: false, advisory.Reputation: true} {
		recordAdvisoryFinding(advisory.Finding{
			Sample:  entry,
			Verdict: advisory.Verdict{Label: "sqli", Score: 100, Reason: "certain"},
			Mode:    mode,
		})
		th := awaitAdvisoryThreat(t, threats)
		if th.HeldAgainstSource() != held {
			t.Errorf("%s mode: held against the source = %v", mode, th.HeldAgainstSource())
		}
		if th.Score != advisoryScoreCap || th.Score >= 80 || th.Mitigated {
			t.Errorf("%s mode: score %v, mitigated %v", mode, th.Score, th.Mitigated)
		}
		if th.Severity != "high" || th.Category != advisoryCategory {
			t.Errorf("%s mode: severity %q, category %q", mode, th.Severity, th.Category)
		}
	}
}

func advisedSample(t *testing.T) *advisory.Sample {
	t.Helper()
	s, ok := advisory.Capture(from("203.0.113.9", sampleGet("/a?b=c")), "advise-direct", advisory.WhySampled, []uint32{942100})
	if !ok {
		t.Fatal("no sample")
	}
	return s
}

// A route's two settings fall back to the environment, and to off.
func TestAdvisory_SettingsFallBackToTheEnvironment(t *testing.T) {
	if cfg := parseWAFConfig(map[string]string{}); cfg.AdvisoryReview || cfg.AdvisorySampleRate != 0 {
		t.Errorf("defaults: %v, %d", cfg.AdvisoryReview, cfg.AdvisorySampleRate)
	}
	t.Setenv(advisoryReviewEnv, "true")
	t.Setenv(advisorySampleRateEnv, "50")
	if cfg := parseWAFConfig(map[string]string{}); !cfg.AdvisoryReview || cfg.AdvisorySampleRate != 50 {
		t.Errorf("from the environment: %v, %d", cfg.AdvisoryReview, cfg.AdvisorySampleRate)
	}
	cfg := parseWAFConfig(map[string]string{keyAdvisoryReview: "false", keyAdvisorySampleRate: "0"})
	if cfg.AdvisoryReview || cfg.AdvisorySampleRate != 0 {
		t.Errorf("the route's own setting lost to the environment: %v, %d", cfg.AdvisoryReview, cfg.AdvisorySampleRate)
	}
	on := parseWAFConfig(map[string]string{keyAdvisoryReview: "true"})
	off := parseWAFConfig(map[string]string{keyAdvisoryReview: "false"})
	if on.Fingerprint() == off.Fingerprint() {
		t.Error("two WAFs that differ in whether they ask the worker share a fingerprint")
	}
}
