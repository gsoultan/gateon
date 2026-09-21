// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/prometheus/client_golang/prometheus"
)

func TestTraceDuplicateInsertion(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_traces.db")

	// Initialize store with SQLite
	err := InitPathStatsStore("sqlite://"+dbPath, 1)
	if err != nil {
		t.Fatalf("Failed to init store: %v", err)
	}
	defer ClosePathStatsStore(context.Background())

	// Wait for store to be ready (it runs a loop)
	time.Sleep(100 * time.Millisecond)

	traceID := "test-trace-1"

	// Record the same trace twice
	RecordTrace(traceID, "GET /test", "service-1", "service-1", 10.5, time.Now(), "success", "/test", "127.0.0.1", "", "US", "Go-http-client/1.1", "GET", "", "example.com/test", "", "", nil, nil, "", 100, 0, 0, 0, 0)
	RecordTrace(traceID, "GET /test", "service-1", "service-1", 10.5, time.Now(), "success", "/test", "127.0.0.1", "", "US", "Go-http-client/1.1", "GET", "", "example.com/test", "", "", nil, nil, "", 100, 0, 0, 0, 0)

	// Flush is triggered every 2s or when batch is full (1024)
	time.Sleep(2500 * time.Millisecond)

	// Verify that we can still get traces
	traces := GetTraces(t.Context(), 10)
	found := false
	count := 0
	for _, tr := range traces {
		if tr.ID == traceID {
			found = true
			count++
		}
	}

	if !found {
		t.Errorf("Trace %s not found in DB", traceID)
	}

	if count > 1 {
		t.Errorf("Expected 1 trace for ID %s, got %d", traceID, count)
	}
}

func TestSecurityTelemetryUpdates(t *testing.T) {
	// Initialize store with a file for stability in tests
	dbPath := filepath.Join(t.TempDir(), "gateon_telemetry_test.db")

	_ = InitPathStatsStore(dbPath, 1)
	defer func() {
		_ = ClosePathStatsStore(context.Background())
	}()

	// Clear global telemetry structures to start fresh
	GlobalCMS.Clear()
	GlobalHHH.Clear()

	// Record a security threat
	threat := SecurityThreat{
		SourceIP:    "1.2.3.4",
		Score:       50,
		Type:        "sql_injection",
		Category:    "injection",
		Severity:    "high",
		ActionTaken: "blocked",
	}
	RecordSecurityThreat(threat)

	// Wait for background worker to process threat and update global structures
	time.Sleep(200 * time.Millisecond)

	// Verify GlobalCMS was updated with "global"
	score := GlobalCMS.Estimate("global")
	if score != 50 {
		t.Errorf("expected GlobalCMS global estimate to be 50, got %d", score)
	}

	// Verify GlobalHHH was updated with the IP
	hitters := GlobalHHH.GetHeavyHitters(1)
	found := false
	for _, h := range hitters {
		if strings.Contains(h.Network, "1.2.3.4/32") || strings.Contains(h.Network, "1.0.0.0/8") || strings.Contains(h.Network, "1.2.0.0/16") || strings.Contains(h.Network, "1.2.3.0/24") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected GlobalHHH to contain 1.2.3.4/32 or its prefixes, got %v", hitters)
	}

	// Verify snapshot reflects these values
	snap, err := CollectMetricsSnapshot(t.Context(), 10, 0)
	if err != nil {
		t.Fatalf("CollectMetricsSnapshot error: %v", err)
	}

	if snap.Security.GlobalThreatScore != 50 {
		t.Errorf("expected snapshot GlobalThreatScore to be 50, got %f", snap.Security.GlobalThreatScore)
	}
}

func TestSecurityTelemetryDailyReset(t *testing.T) {
	// Seed some data
	GlobalCMS.AddWeighted("global", 100)
	GlobalHHH.Add("1.1.1.1")

	// Trigger daily reset via syncDailyBaselines (internal method, but exported if we are in telemetry package)
	if store != nil {
		store.syncDailyBaselines(true)
	} else {
		// If store is nil, we can't easily trigger it, but syncDailyBaselines is what we want to test.
		_ = InitPathStatsStore("sqlite::memory:", 1)
		store.syncDailyBaselines(true)
	}

	if GlobalCMS.Estimate("global") != 0 {
		t.Error("expected GlobalCMS to be cleared after daily reset")
	}
	if len(GlobalHHH.GetHeavyHitters(1)) != 0 {
		t.Error("expected GlobalHHH to be cleared after daily reset")
	}
}

func TestPruneRemovesExpiredStatsAndReclaimsDisk(t *testing.T) {
	// Start from a clean singleton so this test owns the store.
	_ = ClosePathStatsStore(context.Background())

	dbPath := filepath.Join(t.TempDir(), "prune.db")
	if err := InitPathStatsStore("sqlite://"+dbPath, 7); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer ClosePathStatsStore(context.Background())

	st := store
	if st == nil {
		t.Fatal("store not initialized")
	}

	// Retain only today's data so the seeded old row must be pruned.
	st.pathStatsRetentionDays.Store(1)
	old := time.Now().AddDate(0, 0, -30).UTC().Format("2006-01-02")
	fresh := time.Now().UTC().Format("2006-01-02")

	insert := st.dialect.Rebind(`INSERT INTO path_stats
		(day, host, path, req_count, latency_sum_s, bytes_total, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`)
	for _, day := range []string{old, fresh} {
		if _, err := st.db.Exec(insert, day, "example.com", "/x", 1, 0.1, 100); err != nil {
			t.Fatalf("seed row (%s): %v", day, err)
		}
	}

	st.prune()

	var remaining int
	q := st.dialect.Rebind("SELECT COUNT(*) FROM path_stats WHERE day = ?")
	if err := st.db.QueryRow(q, old).Scan(&remaining); err != nil {
		t.Fatalf("count old rows: %v", err)
	}
	if remaining != 0 {
		t.Errorf("expected expired path_stats to be pruned, %d remain", remaining)
	}

	var kept int
	if err := st.db.QueryRow(q, fresh).Scan(&kept); err != nil {
		t.Fatalf("count fresh rows: %v", err)
	}
	if kept != 1 {
		t.Errorf("expected fresh path_stats row to be kept, got %d", kept)
	}
}

func TestRestoreWAFBlockCounter(t *testing.T) {
	// Own the singleton so persisted state is isolated to this test.
	_ = ClosePathStatsStore(context.Background())

	dbPath := filepath.Join(t.TempDir(), "waf_restore.db")
	if err := InitPathStatsStore("sqlite://"+dbPath, 7); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer ClosePathStatsStore(context.Background())

	// Wait for the store loop to be ready.
	time.Sleep(100 * time.Millisecond)

	const route = "route-waf-restore"
	const want = 3
	for i := range want {
		RecordSecurityThreat(SecurityThreat{
			ID:          fmt.Sprintf("waf-restore-%d", i),
			Type:        "waf_block",
			SourceIP:    "9.9.9.9",
			RouteID:     route,
			Category:    "sqli",
			Severity:    "high",
			ActionTaken: "blocked",
			Time:        time.Now(),
		})
	}

	// Threats are persisted by the async batch flush (every ~1s).
	time.Sleep(2500 * time.Millisecond)

	// restoreWAFBlockCounter must replay the persisted blocks into the volatile
	// Prometheus counter so the dashboard does not show 0 after a restart.
	before := wafRestoredCounterValue(t, route)
	store.restoreWAFBlockCounter()
	after := wafRestoredCounterValue(t, route)

	if got := after - before; got != want {
		t.Errorf("restoreWAFBlockCounter: counter delta = %v, want %d", got, want)
	}
}

// wafRestoredCounterValue reads the gateon_middleware_waf_blocked_total counter
// for the given route and the "restored" rule_id label from the default
// Prometheus registry.
func wafRestoredCounterValue(t *testing.T, route string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, fam := range families {
		if fam.GetName() != "gateon_middleware_waf_blocked_total" {
			continue
		}
		for _, m := range fam.GetMetric() {
			var gotRoute, gotRule string
			for _, lbl := range m.GetLabel() {
				switch lbl.GetName() {
				case "route":
					gotRoute = lbl.GetValue()
				case "rule_id":
					gotRule = lbl.GetValue()
				}
			}
			if gotRoute == route && gotRule == "restored" {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func TestGetMitigatedRolling24h(t *testing.T) {
	ctx := context.Background()
	// Own the singleton so the daily counters are isolated to this test.
	_ = ClosePathStatsStore(ctx)

	dbPath := filepath.Join(t.TempDir(), "mitigated_rolling.db")
	if err := InitPathStatsStore("sqlite://"+dbPath, 7); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer ClosePathStatsStore(ctx)
	time.Sleep(100 * time.Millisecond)

	start := GetMitigatedRolling24h(ctx)

	// Mitigating actions increment the counter; detected/observed do not.
	RecordSecurityThreat(SecurityThreat{ID: "m-1", Type: "waf_block", SourceIP: "9.9.9.1", Category: "sqli", Severity: "high", ActionTaken: "blocked", Time: time.Now()})
	RecordSecurityThreat(SecurityThreat{ID: "m-2", Type: "bot", SourceIP: "9.9.9.2", Category: "bot", Severity: "medium", ActionTaken: "challenged", Time: time.Now()})
	RecordSecurityThreat(SecurityThreat{ID: "m-3", Type: "shun", SourceIP: "9.9.9.3", Category: "abuse", Severity: "high", ActionTaken: ActionShunned, Time: time.Now()})
	// Non-mitigating: must NOT count toward "mitigated rolling 24h".
	RecordSecurityThreat(SecurityThreat{ID: "m-4", Type: "scan", SourceIP: "9.9.9.4", Category: "recon", Severity: "low", ActionTaken: "detected", Time: time.Now()})

	// Wait for async persistence
	time.Sleep(2500 * time.Millisecond)

	if got := GetMitigatedRolling24h(ctx) - start; got != 3 {
		t.Fatalf("GetMitigatedRolling24h delta = %d, want 3 (only blocked/challenged/shunned)", got)
	}
}

func TestGenerateIDUniqueness(t *testing.T) {
	ids := make(map[string]bool)
	// Real uniqueness test
	for range 1000 {
		id := request.GenerateID()
		if ids[id] {
			t.Errorf("Duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}

func TestGetTopThreatSources(t *testing.T) {
	// Start fresh
	_ = ClosePathStatsStore(context.Background())

	dbPath := filepath.Join(t.TempDir(), "top_threats.db")
	if err := InitPathStatsStore("sqlite://"+dbPath, 7); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer ClosePathStatsStore(context.Background())

	// Wait for store loop
	time.Sleep(100 * time.Millisecond)

	// Record a few threats from the same IP with an ASN string
	const ip = "1.2.3.4"
	const asn = "AS7713 PT Telekomunikasi Indonesia"
	for range 3 {
		RecordSecurityThreat(SecurityThreat{
			ID:          request.GenerateID(),
			SourceIP:    ip,
			ASN:         asn,
			Type:        "attack",
			ActionTaken: "blocked",
			Time:        time.Now(),
		})
	}

	// Flush (batch flush is ~1s)
	time.Sleep(2500 * time.Millisecond)

	// This should NOT fail if fixed, but currently it triggers "scan failed" log and returns empty/wrong data
	top := GetTopThreatSources(t.Context(), 10)

	if len(top) == 0 {
		t.Fatal("Expected 1 top threat source, got 0. Check if scan failed in logs.")
	}

	if top[0].Label != ip {
		t.Errorf("Expected label %s, got %s", ip, top[0].Label)
	}
	if top[0].Value != 3 {
		t.Errorf("Expected value 3, got %f", top[0].Value)
	}
	if top[0].Subtext != asn {
		t.Errorf("Expected subtext %s, got %s", asn, top[0].Subtext)
	}
}

// flushUntilTraceVisible drives the store's writer until the trace can be read
// back. The writer takes its intake channel and its flush request from one
// select, so a single flush may run before the trace has been taken off the
// channel; each FlushThreats round trip is one full pass of that loop, and a
// bounded number of them is a deterministic wait with no sleep in it.
func flushUntilTraceVisible(t *testing.T, id string) *TraceRecord {
	t.Helper()
	for range 64 {
		FlushThreats()
		for _, tr := range GetTraces(t.Context(), 100) {
			if tr.ID == id {
				return tr
			}
		}
	}
	t.Fatalf("trace %s never became visible in the store", id)
	return nil
}

// TestRecordedTraceRedactsCredentialHeaders records a trace carrying every
// credential-bearing header a client or origin can send and reads it back from
// the trace store, the way the dashboard's trace view does.
//
// Redaction happens in the store's background loop, after the request has been
// answered, so this is the only place it can be checked: a header that reaches
// Pebble in the clear is on disk and in every trace listing and export from
// then on. Proxy-Authorization was missing from the list -- it carries a
// credential exactly as Authorization does, and a gateway is the kind of
// intermediary it is addressed to.
func TestRecordedTraceRedactsCredentialHeaders(t *testing.T) {
	_ = ClosePathStatsStore(context.Background())
	dbPath := filepath.Join(t.TempDir(), "redact.db")
	if err := InitPathStatsStore("sqlite://"+dbPath, 1); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer func() { _ = ClosePathStatsStore(context.Background()) }()

	const secret = "s3cr3t-credential"
	reqHeaders := map[string][]string{
		"Authorization":       {"Bearer " + secret},
		"Proxy-Authorization": {"Basic " + secret},
		"Cookie":              {"session=" + secret},
		"X-Api-Key":           {secret},
		"Accept":              {"text/html"},
	}
	respHeaders := map[string][]string{
		"Set-Cookie":   {"session=" + secret + "; HttpOnly"},
		"Content-Type": {"text/html"},
	}
	const traceID = "trace-with-credentials"
	RecordTrace(traceID, "GET /login", "svc", "route-1", 1.5, time.Now(), "success", "/login",
		"203.0.113.9", "", "", "ua", "GET", "", "example.com/login", "", "",
		reqHeaders, respHeaders, "", 100, 0, 0, 0, 0)

	tr := flushUntilTraceVisible(t, traceID)
	stored := tr.RequestHeaders + "\n" + tr.ResponseHeaders
	if strings.Contains(stored, secret) {
		t.Fatalf("a credential reached the trace store in the clear:\n%s", stored)
	}
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key", "Set-Cookie"} {
		if !strings.Contains(stored, name+": [REDACTED]") {
			t.Errorf("%s was not redacted:\n%s", name, stored)
		}
	}
	if !strings.Contains(tr.RequestHeaders, "Accept: text/html") {
		t.Errorf("a harmless header was lost with the redaction:\n%s", tr.RequestHeaders)
	}
}

// TestManualUnmitigationIsVisible covers the release half of fingerprint
// mitigation on both engines gateon ships.
//
// escalateMitigation consults IsUserUnmitigated before blocking a fingerprint
// again, so that an operator's Remove Mitigation holds for a day rather than
// being undone by the next threat the same client produces. The query behind it
// used SQLite's datetime('now', '-1 day'), which Postgres does not have: there
// the query errored, the error was read as "not released", and the release was
// undone the moment the client tripped anything again. The sibling query in
// IsUserMitigated already bound a Go-side cutoff instead, and this test runs
// against Postgres whenever GATEON_TEST_POSTGRES_DSN is set, the way the
// migration suite does.
func TestManualUnmitigationIsVisible(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		assertManualUnmitigationVisible(t, "sqlite://"+filepath.Join(t.TempDir(), "unmitigate.db"))
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("GATEON_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("GATEON_TEST_POSTGRES_DSN not set; skipping the Postgres run")
		}
		assertManualUnmitigationVisible(t, dsn)
	})
}

func assertManualUnmitigationVisible(t *testing.T, databaseURL string) {
	t.Helper()
	// A non-SQLite store would otherwise put its Pebble directory under
	// config.DataDir, which in a test process is the package directory.
	t.Setenv("GATEON_TRACE_DIR", t.TempDir())
	_ = ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore(databaseURL, 1); err != nil {
		t.Fatalf("init store: %v", err)
	}
	defer func() { _ = ClosePathStatsStore(context.Background()) }()

	s := getStore()
	fp := fmt.Sprintf("t13d1516h2_review_%d|203.0.113", time.Now().UnixNano())
	// Runs before the deferred Close above: a shared Postgres must not keep the
	// row.
	defer func() {
		_, _ = s.db.Exec(s.dialect.Rebind("DELETE FROM user_mitigations WHERE fingerprint = ?"), fp)
	}()

	MarkUserUnmitigated(fp)
	if !IsUserUnmitigated(fp) {
		t.Fatalf("on %s a fingerprint released a moment ago is not reported as unmitigated, "+
			"so escalateMitigation will block it again on the next threat it produces", s.dialect.Driver)
	}
}
