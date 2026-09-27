// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// openStore points the process-global trace store at a directory of this
// test's own and closes it afterwards. InitPathStatsStore does nothing while a
// store is already open, so the close before it is what makes it real (see
// freshStore in internal/telemetry).
func openStore(t *testing.T) {
	t.Helper()
	t.Setenv("GATEON_PROFILE", "standard")
	dir := t.TempDir()
	t.Setenv("GATEON_TRACE_DIR", filepath.Join(dir, "pebble"))
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(dir, "telemetry.db"), 7); err != nil {
		t.Fatalf("InitPathStatsStore: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })
}

// enableArchive turns archiving on, into a directory of this test's own.
func enableArchive(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(EnvDir, dir)
	t.Setenv(EnvEnabled, "true")
	t.Setenv(EnvRetentionDays, "")
	t.Setenv(EnvMaxMB, "")
	return dir
}

// testTrace is a trace as a test states it.
type testTrace struct {
	id     string
	at     time.Time
	status string
	method string
	path   string
}

// store records traces and waits until the store has written them.
// FlushThreats is the store's flush barrier for every intake, traces included.
func store(t *testing.T, traces ...testTrace) {
	t.Helper()
	for _, tr := range traces {
		status, method, path := tr.status, tr.method, tr.path
		if status == "" {
			status = "200"
		}
		if method == "" {
			method = "GET"
		}
		if path == "" {
			path = "/orders"
		}
		telemetry.RecordTrace(tr.id, method+" "+path, "svc", "route-1", 1.5, tr.at, status, path,
			"203.0.113.9", "", "NL", "curl/8", method, "", path, "", "",
			map[string][]string{"Accept": {"*/*"}}, nil, "none", 90, 0, 0, 0, 0)
	}
	telemetry.FlushThreats()
}

// line is the JSON the archive stores for a trace, built the way the store
// builds it.
func line(t *testing.T, tr testTrace) []byte {
	t.Helper()
	rec := telemetry.TraceRecord{ID: tr.id, Timestamp: tr.at, Status: tr.status, Method: tr.method, Path: tr.path}
	if rec.Status == "" {
		rec.Status = "200"
	}
	if rec.Method == "" {
		rec.Method = "GET"
	}
	if rec.Path == "" {
		rec.Path = "/archived"
	}
	b, err := json.Marshal(&rec)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeFile writes a segment holding the given traces, as the archive would,
// without going through the store.
func writeFile(t *testing.T, root string, seg Segment, traces ...testTrace) {
	t.Helper()
	w, err := newSegmentWriter(root, seg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range traces {
		w.fromStore(false)
		if err := w.add(line(t, tr), tr.at.UnixNano()); err != nil {
			t.Fatal(err)
		}
	}
	if _, published, err := w.commit(); err != nil || !published {
		t.Fatalf("commit: published=%v err=%v", published, err)
	}
}

// ids reads the IDs of a segment file's traces in the order the file holds them.
func ids(t *testing.T, path string) []string {
	t.Helper()
	f, err := openSegment(path)
	if err != nil {
		t.Fatalf("openSegment(%s): %v", path, err)
	}
	defer f.Close()
	var out []string
	c := newLineCursor(f)
	for {
		l, ok, err := c.next()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			return out
		}
		var rec telemetry.TraceRecord
		if err := json.Unmarshal(l, &rec); err != nil {
			t.Fatalf("line %q: %v", l, err)
		}
		out = append(out, rec.ID)
	}
}

func hour(t *testing.T, stamp string) Segment {
	t.Helper()
	seg, err := ParseSegmentName(segmentPrefix + stamp + "Z" + segmentSuffix)
	if err != nil {
		t.Fatalf("hour %q: %v", stamp, err)
	}
	return seg
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func seq(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%02d", prefix, i)
	}
	return out
}

// The whole timeline, as a scan window.
const (
	minNanos = -1 << 63
	maxNanos = 1<<63 - 1
)
