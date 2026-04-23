package telemetry

import (
	"context"
	"os"
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
	RecordTrace(traceID, "GET /test", "service-1", 10.5, time.Now(), "success", "/test", "127.0.0.1", "US", "Go-http-client/1.1", "GET", "", "example.com/test", "")
	RecordTrace(traceID, "GET /test", "service-1", 10.5, time.Now(), "success", "/test", "127.0.0.1", "US", "Go-http-client/1.1", "GET", "", "example.com/test", "")

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
