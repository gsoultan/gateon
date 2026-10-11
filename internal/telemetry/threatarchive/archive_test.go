// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package threatarchive

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

func testArchiver(dir string, maxBytes int64) *Archiver {
	return &Archiver{settings: func() Settings { return Settings{Enabled: true, MaxBytes: maxBytes, Dir: dir} }}
}

func threats(n int, start time.Time) []*telemetry.SecurityThreat {
	out := make([]*telemetry.SecurityThreat, n)
	for i := range out {
		out[i] = &telemetry.SecurityThreat{
			ID: fmt.Sprintf("t-%d", i), Type: "sqli", Category: "waf", SourceIP: fmt.Sprintf("203.0.113.%d", i),
			Time: start.Add(time.Duration(i) * time.Minute), RequestURI: "/login",
			RequestBody: "' OR 1=1 --", Score: 90, Observed: i%2 == 0,
		}
	}
	return out
}

// What the archive is for: every field a threat had in the database comes back
// out, bodies included, in the order it went in.
func TestArchiveRoundTripsThreats(t *testing.T) {
	dir := t.TempDir()
	in := threats(3, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err := testArchiver(dir, 0).Archive(context.Background(), in); err != nil {
		t.Fatalf("Archive: %v", err)
	}
	files, total, err := List(dir, 0, 0)
	if err != nil || total != 1 {
		t.Fatalf("List = %v, %d, %v; want one file", files, total, err)
	}
	if !files[0].FirstAt.Equal(in[0].Time) || !files[0].LastAt.Equal(in[2].Time) {
		t.Fatalf("file spans %v..%v, want %v..%v", files[0].FirstAt, files[0].LastAt, in[0].Time, in[2].Time)
	}
	out, matched, err := Read(context.Background(), dir, files[0].Name, "", 0, 0)
	if err != nil || matched != 3 || len(out) != 3 {
		t.Fatalf("Read = %d threats, %d matched, %v; want 3", len(out), matched, err)
	}
	for i := range in {
		if out[i].ID != in[i].ID || out[i].RequestBody != in[i].RequestBody || !out[i].Time.Equal(in[i].Time) || out[i].Observed != in[i].Observed {
			t.Fatalf("threat %d came back as %+v, want %+v", i, out[i], in[i])
		}
	}
}

func TestReadSearchesAndPages(t *testing.T) {
	dir := t.TempDir()
	in := threats(12, time.Now().UTC())
	in[4].Details, in[9].Details = "Path Traversal", "path traversal again"
	if err := testArchiver(dir, 0).Archive(context.Background(), in); err != nil {
		t.Fatalf("Archive: %v", err)
	}
	files, _, _ := List(dir, 0, 0)

	got, matched, err := Read(context.Background(), dir, files[0].Name, "PATH traversal", 1, 1)
	if err != nil || matched != 2 || len(got) != 1 || got[0].ID != "t-9" {
		t.Fatalf("search page = %v, matched %d, err %v; want [t-9] of 2", got, matched, err)
	}
	got, matched, _ = Read(context.Background(), dir, files[0].Name, "", 5, 10)
	if matched != 12 || len(got) != 2 {
		t.Fatalf("last page = %d of %d, want 2 of 12", len(got), matched)
	}
}

// The name is the only thing a caller controls, so it is the traversal
// surface. Only the exact archive shape may be opened.
func TestReadRefusesAnythingButAnArchiveName(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(filepath.Dir(dir), "secret.ndjson.gz")
	for _, name := range []string{
		"../secret.ndjson.gz", secret, "threats_x.ndjson.gz", "",
		"threats_20260101T000000Z_20260101T000000Z_deadbeef.ndjson.gz/..",
		"../threats_20260101T000000Z_20260101T000000Z_deadbeef.ndjson.gz",
	} {
		if _, _, err := Read(context.Background(), dir, name, "", 0, 0); !errors.Is(err, ErrNotAnArchive) {
			t.Errorf("Read(%q) = %v, want ErrNotAnArchive", name, err)
		}
	}
}

// Past the size budget the oldest files go, but never the one just written:
// its rows are deleted the moment Archive returns.
func TestArchiveHoldsItsSizeBudgetAndKeepsTheNewestFile(t *testing.T) {
	dir := t.TempDir()
	a := testArchiver(dir, 1) // smaller than any file
	start := time.Now().UTC()
	for i := range 3 {
		if err := a.Archive(context.Background(), threats(5, start.Add(time.Duration(i)*time.Hour))); err != nil {
			t.Fatalf("Archive %d: %v", i, err)
		}
	}
	files, total, _ := List(dir, 0, 0)
	if total != 1 {
		t.Fatalf("got %d files, want only the newest kept", total)
	}
	if want := start.Add(2 * time.Hour); !files[0].FirstAt.Equal(want.Truncate(time.Second)) {
		t.Fatalf("kept the file starting %v, want the newest (%v)", files[0].FirstAt, want)
	}
}

// A failed write must leave nothing that looks like an archive, and must say
// so: the caller deletes the rows only on success.
func TestArchiveFailureLeavesNoFile(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := testArchiver(blocker, 0).Archive(context.Background(), threats(1, time.Now())); err == nil {
		t.Fatal("Archive into a file path must fail")
	}

	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := testArchiver(dir, 0).Archive(ctx, threats(2, time.Now())); err == nil {
		t.Fatal("Archive with a cancelled context must fail")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left %v behind after a failed write", entries)
	}
}

func TestListPagesNewestFirst(t *testing.T) {
	dir := t.TempDir()
	a := testArchiver(dir, 0)
	start := time.Now().UTC()
	for i := range 4 {
		if err := a.Archive(context.Background(), threats(1, start.Add(time.Duration(i)*time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	page, total, err := List(dir, 2, 1)
	if err != nil || total != 4 || len(page) != 2 {
		t.Fatalf("List = %d of %d, %v; want 2 of 4", len(page), total, err)
	}
	if !page[0].FirstAt.After(page[1].FirstAt) {
		t.Fatal("List must be newest first")
	}
	if missing, n, err := List(filepath.Join(dir, "absent"), 0, 0); err != nil || n != 0 || len(missing) != 0 {
		t.Fatalf("a missing directory is an empty archive, got %v %d %v", missing, n, err)
	}
}

func TestSettingsEnvOverridesAndIgnoresTypos(t *testing.T) {
	t.Setenv(EnvEnabled, "true")
	t.Setenv(EnvMaxMB, "7")
	t.Setenv(EnvDir, "/var/tmp/x")
	s := Settings{MaxBytes: 1}
	s.applyEnv()
	if !s.Enabled || s.MaxBytes != 7<<20 || s.Dir != "/var/tmp/x" {
		t.Fatalf("env not applied: %+v", s)
	}
	t.Setenv(EnvEnabled, "yes please")
	t.Setenv(EnvMaxMB, "-3")
	s = Settings{MaxBytes: 1}
	s.applyEnv()
	if s.Enabled || s.MaxBytes != 1 {
		t.Fatalf("a malformed variable must be ignored: %+v", s)
	}
}
