package telemetry

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/request"
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
	RecordTrace(traceID, "GET /test", "service-1", "service-1", 10.5, time.Now(), "success", "/test", "127.0.0.1", "", "US", "Go-http-client/1.1", "GET", "", "example.com/test", "", "", `{"User-Agent":"Go-http-client/1.1"}`, `{"Content-Type":"text/plain"}`)
	RecordTrace(traceID, "GET /test", "service-1", "service-1", 10.5, time.Now(), "success", "/test", "127.0.0.1", "", "US", "Go-http-client/1.1", "GET", "", "example.com/test", "", "", `{"User-Agent":"Go-http-client/1.1"}`, `{"Content-Type":"text/plain"}`)

	// Flush is triggered every 1s or when batch is full (1024)
	time.Sleep(1500 * time.Millisecond)

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
	// Initialize store if not already done (minimal)
	_ = InitPathStatsStore("sqlite::memory:", 1)
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
