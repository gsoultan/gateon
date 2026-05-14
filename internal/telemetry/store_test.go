package telemetry

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/request"
)

func TestTraceDuplicateInsertion(t *testing.T) {
	dbPath := "test_traces.db"
	defer os.Remove(dbPath)

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
	RecordTrace(traceID, "GET /test", "service-1", 10.5, time.Now(), "success", "/test", "127.0.0.1", "", "US", "Go-http-client/1.1", "GET", "", "example.com/test", "", "")
	RecordTrace(traceID, "GET /test", "service-1", 10.5, time.Now(), "success", "/test", "127.0.0.1", "", "US", "Go-http-client/1.1", "GET", "", "example.com/test", "", "")

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
		if strings.Contains(h, "1.2.3.4/32") || strings.Contains(h, "1.0.0.0/8") || strings.Contains(h, "1.2.0.0/16") || strings.Contains(h, "1.2.3.0/24") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected GlobalHHH to contain 1.2.3.4/32 or its prefixes, got %v", hitters)
	}

	// Verify snapshot reflects these values
	snap, err := CollectMetricsSnapshot(10, 0)
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

func TestGenerateIDUniqueness(t *testing.T) {
	ids := make(map[string]bool)
	// Real uniqueness test
	for i := 0; i < 1000; i++ {
		id := request.GenerateID()
		if ids[id] {
			t.Errorf("Duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}
