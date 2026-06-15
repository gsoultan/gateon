package correlation

import (
	"sync"
	"testing"
	"time"
)

func TestTechniquesMapping(t *testing.T) {
	tests := []struct {
		name      string
		threat    string
		wantFirst string
		wantEmpty bool
	}{
		{"brute force", "brute_force_attempt", "T1110", false},
		{"exploit scan", "exploit_scan", "T1190", false},
		{"impossible travel", "impossible_travel", "T1078", false},
		{"unknown", "totally_unknown", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Techniques(tc.threat)
			if tc.wantEmpty {
				if len(got) != 0 {
					t.Fatalf("Techniques(%q) = %v, want empty", tc.threat, got)
				}
				return
			}
			if len(got) == 0 || got[0].ID != tc.wantFirst {
				t.Fatalf("Techniques(%q) first = %v, want %q", tc.threat, got, tc.wantFirst)
			}
		})
	}
}

func TestTechniquesReturnsCopy(t *testing.T) {
	got := Techniques("brute_force_attempt")
	got[0].ID = "MUTATED"
	again := Techniques("brute_force_attempt")
	if again[0].ID != "T1110" {
		t.Fatalf("Techniques returned a shared slice; got %q", again[0].ID)
	}
}

// newTestEngine returns an engine with an injected, controllable clock.
func newTestEngine(cfg Config, now *time.Time) *Engine {
	e := New(cfg)
	e.clock = func() time.Time { return *now }
	return e
}

func TestObserveRaisesIncidentAtThreshold(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var captured []Incident
	var mu sync.Mutex
	e := newTestEngine(Config{
		Window:     time.Minute,
		MinSignals: 3,
		OnIncident: func(inc Incident) {
			mu.Lock()
			captured = append(captured, inc)
			mu.Unlock()
		},
	}, &now)

	sig := func(typ string) Signal {
		return Signal{Type: typ, SourceIP: "1.2.3.4", Severity: "high", Score: 10, Time: now}
	}

	if _, fired := e.Observe(sig("probe_detected")); fired {
		t.Fatal("first signal should not fire")
	}
	if _, fired := e.Observe(sig("exploit_scan")); fired {
		t.Fatal("second signal should not fire")
	}
	inc, fired := e.Observe(sig("brute_force_attempt"))
	if !fired {
		t.Fatal("third signal should raise an incident")
	}
	if inc.SignalCount != 3 || inc.SourceIP != "1.2.3.4" || inc.Severity != "high" {
		t.Fatalf("unexpected incident: %+v", inc)
	}
	if len(inc.Techniques) == 0 {
		t.Fatal("incident should carry MITRE techniques")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(captured) != 1 {
		t.Fatalf("OnIncident fired %d times, want 1", len(captured))
	}
}

func TestObserveDebouncesReAlert(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := newTestEngine(Config{
		Window:          time.Minute,
		MinSignals:      2,
		ReAlertInterval: 30 * time.Second,
	}, &now)

	mk := func() Signal { return Signal{Type: "exploit_scan", SourceIP: "9.9.9.9", Time: now} }

	e.Observe(mk())
	if _, fired := e.Observe(mk()); !fired {
		t.Fatal("should fire on reaching threshold")
	}
	// Another signal immediately: still within ReAlertInterval -> debounced.
	if _, fired := e.Observe(mk()); fired {
		t.Fatal("should be debounced within ReAlertInterval")
	}
	// Advance past the re-alert interval -> fires again.
	now = now.Add(31 * time.Second)
	if _, fired := e.Observe(mk()); !fired {
		t.Fatal("should re-alert after ReAlertInterval elapses")
	}
}

func TestWindowExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := newTestEngine(Config{Window: time.Minute, MinSignals: 3}, &now)
	mk := func() Signal { return Signal{Type: "probe_detected", SourceIP: "8.8.8.8", Time: now} }

	e.Observe(mk())
	e.Observe(mk())
	// Advance beyond the window so the earlier two signals expire.
	now = now.Add(2 * time.Minute)
	if _, fired := e.Observe(mk()); fired {
		t.Fatal("expired signals must not count toward the threshold")
	}
}

func TestScoreThreshold(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := newTestEngine(Config{Window: time.Minute, MinSignals: 100, MinScore: 50}, &now)
	mk := func() Signal { return Signal{Type: "waf_block", SourceIP: "7.7.7.7", Score: 30, Time: now} }

	if _, fired := e.Observe(mk()); fired {
		t.Fatal("30 < 50 should not fire")
	}
	if _, fired := e.Observe(mk()); !fired {
		t.Fatal("cumulative 60 >= 50 should fire on score threshold")
	}
}

func TestGCRemovesIdleSources(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := newTestEngine(Config{Window: time.Minute, MinSignals: 5}, &now)
	e.Observe(Signal{Type: "probe_detected", SourceIP: "1.1.1.1", Time: now})
	if got := e.TrackedSources(); got != 1 {
		t.Fatalf("tracked sources = %d, want 1", got)
	}
	now = now.Add(2 * time.Minute)
	e.GC()
	if got := e.TrackedSources(); got != 0 {
		t.Fatalf("tracked sources after GC = %d, want 0", got)
	}
}

func TestObserveIgnoresKeylessSignal(t *testing.T) {
	e := New(Config{MinSignals: 1})
	if _, fired := e.Observe(Signal{Type: "probe_detected"}); fired {
		t.Fatal("signal without source IP or fingerprint must be ignored")
	}
}
