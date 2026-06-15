// Package fim implements File Integrity Monitoring (FIM): it records a
// cryptographic baseline of a set of watched files (served static assets,
// configuration, rule sets) and periodically rescans them to detect drift
// (added, modified, or removed files). It is the dependency-free foundation
// of Gateon's Wazuh-like host detection capabilities.
//
// The scanner is safe for concurrent use: Scan mutates the baseline under a
// write lock while Status reads a snapshot under a read lock.
package fim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ChangeType classifies a detected integrity change.
type ChangeType string

const (
	// ChangeAdded marks a file that appeared since the baseline.
	ChangeAdded ChangeType = "added"
	// ChangeModified marks a file whose content hash changed.
	ChangeModified ChangeType = "modified"
	// ChangeRemoved marks a file that disappeared since the baseline.
	ChangeRemoved ChangeType = "removed"
)

// Default tuning values.
const (
	defaultInterval  = 5 * time.Minute
	defaultMaxEvents = 256
	minInterval      = 10 * time.Second
	// maxHashFileSize bounds per-file reads so a hostile or accidental huge
	// file cannot exhaust memory; larger files are hashed by streaming, so
	// this is only an upper bound on total bytes hashed per file.
	maxHashFileSize = 512 << 20 // 512 MiB
)

// Event describes a single detected integrity change.
type Event struct {
	Path       string     `json:"path"`
	Change     ChangeType `json:"change"`
	OldHash    string     `json:"old_hash,omitzero"`
	NewHash    string     `json:"new_hash,omitzero"`
	DetectedAt time.Time  `json:"detected_at"`
}

// Status is an immutable snapshot of the scanner state, safe to serialize.
type Status struct {
	Enabled       bool          `json:"enabled"`
	WatchedPaths  []string      `json:"watched_paths"`
	BaselineFiles int           `json:"baseline_files"`
	LastScan      time.Time     `json:"last_scan,omitzero"`
	LastScanTook  time.Duration `json:"last_scan_took,omitzero"`
	TotalDrift    int64         `json:"total_drift"`
	RecentEvents  []Event       `json:"recent_events"`
}

// OnDriftFunc is invoked (outside the scanner lock) whenever a scan detects
// one or more changes. It must not block for long.
type OnDriftFunc func([]Event)

// Config configures a Scanner.
type Config struct {
	// Paths is the set of files and/or directories to monitor (directories
	// are walked recursively).
	Paths []string
	// Interval between automatic scans; values below minInterval are raised.
	Interval time.Duration
	// MaxEvents bounds the retained recent-event ring buffer.
	MaxEvents int
	// OnDrift, if set, is called with the events of each drift-detecting scan.
	OnDrift OnDriftFunc
}

// Scanner performs file integrity monitoring over a fixed set of paths.
type Scanner struct {
	paths     []string
	interval  time.Duration
	maxEvents int
	onDrift   OnDriftFunc

	mu           sync.RWMutex
	baseline     map[string]string // path -> hex(sha256)
	lastScan     time.Time
	lastScanTook time.Duration
	totalDrift   int64
	recent       []Event
}

// New creates a Scanner from cfg. It returns an error only when no paths are
// configured; missing paths on disk are tolerated and surfaced as drift.
func New(cfg Config) (*Scanner, error) {
	paths := normalizePaths(cfg.Paths)
	if len(paths) == 0 {
		return nil, errors.New("fim: at least one watched path is required")
	}

	interval := cfg.Interval
	switch {
	case interval <= 0:
		interval = defaultInterval
	case interval < minInterval:
		interval = minInterval
	}

	maxEvents := cfg.MaxEvents
	if maxEvents <= 0 {
		maxEvents = defaultMaxEvents
	}

	return &Scanner{
		paths:     paths,
		interval:  interval,
		maxEvents: maxEvents,
		onDrift:   cfg.OnDrift,
		baseline:  make(map[string]string),
	}, nil
}

// normalizePaths cleans, de-duplicates, and stably orders the input paths.
func normalizePaths(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = filepath.Clean(p)
		if p == "" || p == "." {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Baseline computes the initial integrity baseline. Subsequent Scan calls are
// compared against it. Returns the number of files hashed.
func (s *Scanner) Baseline() (int, error) {
	current, err := s.snapshot()
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.baseline = current
	s.lastScan = time.Now()
	s.mu.Unlock()
	return len(current), nil
}

// Scan recomputes hashes for all watched paths, diffs them against the
// baseline, updates the baseline to the new state, records any drift, and
// returns the detected events.
func (s *Scanner) Scan() ([]Event, error) {
	start := time.Now()
	current, err := s.snapshot()
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	events := diff(s.baseline, current, start)
	s.baseline = current
	s.lastScan = start
	s.lastScanTook = time.Since(start)
	s.recordEventsLocked(events)
	s.mu.Unlock()

	if len(events) > 0 && s.onDrift != nil {
		s.onDrift(events)
	}
	return events, nil
}

// recordEventsLocked appends events to the bounded recent-event buffer and
// bumps the lifetime drift counter. Caller must hold s.mu for writing.
func (s *Scanner) recordEventsLocked(events []Event) {
	if len(events) == 0 {
		return
	}
	s.totalDrift += int64(len(events))
	s.recent = append(s.recent, events...)
	if overflow := len(s.recent) - s.maxEvents; overflow > 0 {
		s.recent = s.recent[overflow:]
	}
}

// Start runs Baseline once, then rescans on the configured interval until ctx
// is cancelled. It blocks and is intended to be launched in its own goroutine.
func (s *Scanner) Start(ctx context.Context) {
	if _, err := s.Baseline(); err != nil {
		// A baseline error (e.g. a fully unreadable root) should not crash the
		// gateway; report via drift on the next successful scan.
		_ = err
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = s.Scan()
		}
	}
}

// Status returns an immutable snapshot of the current scanner state.
func (s *Scanner) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()

	recent := make([]Event, len(s.recent))
	copy(recent, s.recent)

	return Status{
		Enabled:       true,
		WatchedPaths:  append([]string(nil), s.paths...),
		BaselineFiles: len(s.baseline),
		LastScan:      s.lastScan,
		LastScanTook:  s.lastScanTook,
		TotalDrift:    s.totalDrift,
		RecentEvents:  recent,
	}
}

// snapshot walks every watched path and returns a path->hash map of all
// regular files. Unreadable individual files are skipped (they surface as
// removals/additions on diff), but a walk error on a root is returned.
func (s *Scanner) snapshot() (map[string]string, error) {
	out := make(map[string]string)
	for _, root := range s.paths {
		if err := hashTree(root, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// hashTree hashes a single regular file or recursively walks a directory,
// adding regular-file hashes to dst. A non-existent root is not an error.
func hashTree(root string, dst map[string]string) error {
	info, err := os.Lstat(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		addFileHash(root, info, dst)
		return nil
	}

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		fi, statErr := d.Info()
		if statErr != nil {
			return nil // skip transient unreadable entries
		}
		addFileHash(path, fi, dst)
		return nil
	})
}

// addFileHash hashes a single regular file and stores it in dst. Symlinks,
// devices, and other non-regular files are skipped (only their content matters
// for integrity, and following symlinks would risk traversal).
func addFileHash(path string, info fs.FileInfo, dst map[string]string) {
	if !info.Mode().IsRegular() {
		return
	}
	sum, err := hashFile(path)
	if err != nil {
		return // unreadable now; absence is itself drift on next compare
	}
	dst[path] = sum
}

// hashFile returns the hex-encoded SHA-256 of a file's contents, streaming to
// avoid loading the whole file into memory.
func hashFile(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- paths come from operator config, not user input
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxHashFileSize)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// diff compares an old and new path->hash map and returns the changes, ordered
// by path for stable, deterministic output.
func diff(old, current map[string]string, at time.Time) []Event {
	var events []Event
	for path, newHash := range current {
		oldHash, existed := old[path]
		switch {
		case !existed:
			events = append(events, Event{Path: path, Change: ChangeAdded, NewHash: newHash, DetectedAt: at})
		case oldHash != newHash:
			events = append(events, Event{Path: path, Change: ChangeModified, OldHash: oldHash, NewHash: newHash, DetectedAt: at})
		}
	}
	for path, oldHash := range old {
		if _, ok := current[path]; !ok {
			events = append(events, Event{Path: path, Change: ChangeRemoved, OldHash: oldHash, DetectedAt: at})
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Path < events[j].Path })
	return events
}
