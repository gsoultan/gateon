package fim

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestNewValidatesPaths(t *testing.T) {
	if _, err := New(Config{Paths: nil}); err == nil {
		t.Fatal("expected error for empty paths")
	}
	if _, err := New(Config{Paths: []string{"."}}); err == nil {
		t.Fatal("expected error when paths normalize to empty")
	}
}

func TestScanDetectsDrift(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "keep.txt")
	mod := filepath.Join(dir, "sub", "mod.txt")
	gone := filepath.Join(dir, "gone.txt")
	writeFile(t, keep, "unchanged")
	writeFile(t, mod, "v1")
	writeFile(t, gone, "delete me")

	s, err := New(Config{Paths: []string{dir}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	n, err := s.Baseline()
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	if n != 3 {
		t.Fatalf("baseline files = %d, want 3", n)
	}

	// Mutate the tree: modify one, remove one, add one.
	writeFile(t, mod, "v2-changed")
	if err := os.Remove(gone); err != nil {
		t.Fatalf("remove: %v", err)
	}
	added := filepath.Join(dir, "added.txt")
	writeFile(t, added, "new file")

	events, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	got := make(map[string]ChangeType, len(events))
	for _, e := range events {
		got[e.Path] = e.Change
	}
	tests := []struct {
		name string
		path string
		want ChangeType
	}{
		{"added", added, ChangeAdded},
		{"modified", mod, ChangeModified},
		{"removed", gone, ChangeRemoved},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got[tc.path] != tc.want {
				t.Errorf("%s: change = %q, want %q", tc.path, got[tc.path], tc.want)
			}
		})
	}
	if _, ok := got[keep]; ok {
		t.Errorf("unchanged file %s should not appear in events", keep)
	}
}

func TestScanNoDriftWhenStable(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "stable")

	s, err := New(Config{Paths: []string{dir}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Baseline(); err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	events, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no drift, got %d events", len(events))
	}
}

func TestOnDriftCallbackAndStatus(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "watched.txt")
	writeFile(t, f, "original")

	var mu sync.Mutex
	var fired [][]Event
	s, err := New(Config{
		Paths: []string{dir},
		OnDrift: func(ev []Event) {
			mu.Lock()
			fired = append(fired, ev)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Baseline(); err != nil {
		t.Fatalf("Baseline: %v", err)
	}

	writeFile(t, f, "tampered")
	if _, err := s.Scan(); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(fired) != 1 || len(fired[0]) != 1 {
		t.Fatalf("OnDrift callback not invoked as expected: %+v", fired)
	}

	st := s.Status()
	if !st.Enabled || st.TotalDrift != 1 || len(st.RecentEvents) != 1 {
		t.Fatalf("unexpected status: %+v", st)
	}
	if st.RecentEvents[0].Change != ChangeModified {
		t.Errorf("recent event change = %q, want %q", st.RecentEvents[0].Change, ChangeModified)
	}
}

func TestRecentEventsAreBounded(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f.txt")
	writeFile(t, f, "0")

	s, err := New(Config{Paths: []string{dir}, MaxEvents: 3})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Baseline(); err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	for i := range 10 {
		writeFile(t, f, time.Now().Format(time.RFC3339Nano)+string(rune('a'+i)))
		if _, err := s.Scan(); err != nil {
			t.Fatalf("Scan %d: %v", i, err)
		}
	}
	st := s.Status()
	if len(st.RecentEvents) != 3 {
		t.Fatalf("recent events = %d, want capped at 3", len(st.RecentEvents))
	}
	if st.TotalDrift != 10 {
		t.Fatalf("total drift = %d, want 10", st.TotalDrift)
	}
}

func TestSingleFileWatch(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "single.conf")
	writeFile(t, f, "key=value")

	s, err := New(Config{Paths: []string{f}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	n, err := s.Baseline()
	if err != nil || n != 1 {
		t.Fatalf("Baseline n=%d err=%v, want 1, nil", n, err)
	}
	writeFile(t, f, "key=tampered")
	events, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(events) != 1 || events[0].Change != ChangeModified {
		t.Fatalf("expected single modified event, got %+v", events)
	}
}
