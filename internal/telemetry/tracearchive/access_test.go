// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"slices"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// An ID is whatever the request carried, so it can hold characters JSON
// escapes; the lookup has to find it the way the archive spelled it.
func TestLookup_FindsAnArchivedTraceByItsKey(t *testing.T) {
	root := enableArchive(t)
	seg := hour(t, "2026-09-20T10")
	at := seg.Start().Add(17 * time.Minute)
	odd := `req-<"quoted">&amp`
	writeFile(t, root, seg,
		testTrace{id: "neighbour", at: at},
		testTrace{id: odd, at: at},
		testTrace{id: "later", at: at.Add(time.Minute)},
	)

	got, err := Lookup(context.Background(), at, odd)
	if err != nil || got == nil || got.ID != odd || !got.Timestamp.Equal(at) {
		t.Fatalf("Lookup = %+v, %v; want the trace %q", got, err, odd)
	}
	for name, probe := range map[string]struct {
		at time.Time
		id string
	}{
		"right ID, wrong time": {at.Add(time.Nanosecond), odd},
		"right time, wrong ID": {at, "nobody"},
		"hour not archived":    {at.Add(-24 * time.Hour), odd},
	} {
		if got, err := Lookup(context.Background(), probe.at, probe.id); got != nil || err != nil {
			t.Errorf("%s: Lookup = %+v, %v; want nothing", name, got, err)
		}
	}
}

func TestList_PagesNewestFirst(t *testing.T) {
	root := enableArchive(t)
	stamps := []string{"2026-09-20T08", "2026-09-20T09", "2026-09-20T10", "2026-09-21T00", "2026-09-22T05"}
	plant(t, root, stamps...)

	var got []string
	token := ""
	for range 10 {
		page, next, err := List(time.Time{}, time.Time{}, 2, token)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range page {
			if s.Traces != 1 || s.Size <= 0 || s.Archived.IsZero() {
				t.Fatalf("%s: %+v, want its header's count and time", s.Name(), s)
			}
			got = append(got, s.Segment.Start().Format("2006-01-02T15"))
		}
		if token = next; token == "" {
			break
		}
	}
	want := slices.Clone(stamps)
	slices.Reverse(want)
	if !slices.Equal(got, want) {
		t.Fatalf("listed %v, want %v", got, want)
	}

	if _, _, err := List(time.Time{}, time.Time{}, 2, "../../etc"); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("a forged page token: %v, want ErrInvalidQuery", err)
	}
}

func TestOpenDownload_ServesOnlyArchiveFiles(t *testing.T) {
	root := enableArchive(t)
	seg := hour(t, "2026-09-20T10")
	writeFile(t, root, seg,
		testTrace{id: "a", at: seg.Start().Add(time.Minute)},
		testTrace{id: "b", at: seg.Start().Add(2 * time.Minute)},
	)

	for _, name := range []string{"../../../etc/passwd", "2026/09/20/" + seg.FileName(testNode), ""} {
		if _, err := OpenDownload(name); !errors.Is(err, ErrNotASegment) {
			t.Errorf("OpenDownload(%q) = %v, want ErrNotASegment", name, err)
		}
	}
	if _, err := OpenDownload(hour(t, "2026-09-20T11").FileName(testNode)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("an hour with no file: %v, want fs.ErrNotExist", err)
	}

	d, err := OpenDownload(seg.FileName(testNode))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var plain bytes.Buffer
	if _, err := d.WriteNDJSON(context.Background(), &plain); err != nil {
		t.Fatal(err)
	}
	want := append(append(line(t, testTrace{id: "a", at: seg.Start().Add(time.Minute)}), '\n'),
		append(line(t, testTrace{id: "b", at: seg.Start().Add(2 * time.Minute)}), '\n')...)
	if !bytes.Equal(plain.Bytes(), want) {
		t.Fatalf("NDJSON download:\n%s\nwant:\n%s", plain.Bytes(), want)
	}
	stored, err := io.ReadAll(d.Content())
	if err != nil {
		t.Fatal(err)
	}
	onDisk, _ := os.ReadFile(seg.path(root, testNode))
	if !bytes.Equal(stored, onDisk) {
		t.Fatal("the compressed download is not the file as stored")
	}
}

func TestCurrentSettings_EnvironmentBeatsConfigBeatsProfile(t *testing.T) {
	t.Setenv("GATEON_PROFILE", "enterprise")
	for _, v := range []string{EnvEnabled, EnvDir, EnvRetentionDays, EnvMaxMB} {
		t.Setenv(v, "")
	}
	s := CurrentSettings()
	if s.Enabled || s.RetentionDays != 365 || s.MaxBytes != 20<<30 {
		t.Fatalf("profile defaults = %+v; want off, 365 days, 20 GiB", s)
	}

	t.Setenv(EnvEnabled, "true")
	t.Setenv(EnvRetentionDays, "30")
	t.Setenv(EnvMaxMB, "512")
	t.Setenv(EnvDir, "/srv/traces")
	s = CurrentSettings()
	if !s.Enabled || s.RetentionDays != 30 || s.MaxBytes != 512<<20 || s.Dir != "/srv/traces" {
		t.Fatalf("with the environment set = %+v", s)
	}

	// A typo does not overrule what is underneath it.
	t.Setenv(EnvEnabled, "yes please")
	t.Setenv(EnvRetentionDays, "-3")
	t.Setenv(EnvMaxMB, "lots")
	s = CurrentSettings()
	if s.Enabled || s.RetentionDays != 365 || s.MaxBytes != 20<<30 {
		t.Fatalf("malformed variables were obeyed: %+v", s)
	}
}

// What the environment asks for is held to what the archive can use: days and
// megabytes are clamped, and a day count past what 32 bits hold is not a
// number of days but a typo, ignored like one.
func TestCurrentSettings_BoundsWhatTheEnvironmentAsks(t *testing.T) {
	t.Setenv("GATEON_PROFILE", "enterprise")
	t.Setenv(EnvEnabled, "")
	t.Setenv(EnvDir, "")
	t.Setenv(EnvRetentionDays, "5000000")
	t.Setenv(EnvMaxMB, "1125899906842624") // 2^50 MB
	if s := CurrentSettings(); s.RetentionDays != 1<<20 || s.MaxBytes != 1<<60 {
		t.Fatalf("settings = %+v; want 2^20 days and 2^40 MB", s)
	}
	t.Setenv(EnvRetentionDays, "99999999999")
	if s := CurrentSettings(); s.RetentionDays != 365 {
		t.Fatalf("a day count past 32 bits gave %d days, want the profile's 365", s.RetentionDays)
	}
}

// The stored config sits between the two, and a zero in it means "the
// profile's default", not "keep nothing". Applied the way CurrentSettings
// applies it; the global config itself is process state a test cannot put back.
func TestSettings_ConfigSitsBetweenProfileAndEnvironment(t *testing.T) {
	for _, v := range []string{EnvEnabled, EnvDir, EnvRetentionDays, EnvMaxMB} {
		t.Setenv(v, "")
	}
	profile := Settings{RetentionDays: 90, MaxBytes: 2 << 30}

	s := profile
	s.applyConfig(&gateonv1.LogConfig{TraceArchiveEnabled: true, TraceArchiveRetentionDays: 14, TraceArchiveMaxSizeMb: 100})
	s.applyEnv()
	if !s.Enabled || s.RetentionDays != 14 || s.MaxBytes != 100<<20 {
		t.Fatalf("config over profile = %+v", s)
	}

	s = profile
	s.applyConfig(&gateonv1.LogConfig{TraceArchiveEnabled: true})
	if s.RetentionDays != 90 || s.MaxBytes != 2<<30 {
		t.Fatalf("unset config values replaced the profile's: %+v", s)
	}

	t.Setenv(EnvEnabled, "false")
	t.Setenv(EnvRetentionDays, "3")
	s = profile
	s.applyConfig(&gateonv1.LogConfig{TraceArchiveEnabled: true, TraceArchiveRetentionDays: 14})
	s.applyEnv()
	if s.Enabled || s.RetentionDays != 3 {
		t.Fatalf("the environment did not beat the config: %+v", s)
	}
}

// A client that opens downloads and reads none holds one slot each; past four,
// the next is told to come back rather than queued.
func TestOpenDownload_AtMostFourAtOnce(t *testing.T) {
	root := enableArchive(t)
	seg := hour(t, "2026-09-20T10")
	writeFile(t, root, seg, testTrace{id: "a", at: seg.Start().Add(time.Minute)})

	var open []*Download
	for range maxDownloads {
		d, err := OpenDownload(seg.FileName(testNode))
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, d)
	}
	if _, err := OpenDownload(seg.FileName(testNode)); !errors.Is(err, ErrBusy) {
		t.Fatalf("download %d: %v, want ErrBusy", maxDownloads+1, err)
	}
	_ = open[0].Close()
	_ = open[0].Close() // a second Close must not give back a slot it does not hold
	d, err := OpenDownload(seg.FileName(testNode))
	if err != nil {
		t.Fatalf("after one closed: %v", err)
	}
	if _, err := OpenDownload(seg.FileName(testNode)); !errors.Is(err, ErrBusy) {
		t.Fatalf("a double Close freed two slots: %v", err)
	}
	for _, o := range append(open[1:], d) {
		_ = o.Close()
	}
	if _, err := OpenDownload("../nope"); !errors.Is(err, ErrNotASegment) {
		t.Fatal("the name check must come before a slot is taken")
	}
	if _, err := OpenDownload(hour(t, "2026-09-20T11").FileName(testNode)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a missing hour must not keep the slot it took")
	}
	for range maxDownloads {
		d, err := OpenDownload(seg.FileName(testNode))
		if err != nil {
			t.Fatalf("a failed open leaked a slot: %v", err)
		}
		defer d.Close()
	}
}

// A trace found in another node's archive opens: the detail view asks by start
// time and ID, and does not know which node recorded it.
func TestLookup_FindsATraceInAnotherNodesArchive(t *testing.T) {
	root := enableArchive(t)
	seg := hour(t, "2026-09-20T10")
	at := seg.Start().Add(17 * time.Minute)
	writeFile(t, root, seg, testTrace{id: "mine", at: at})
	writeNodeFile(t, root, "gw-other", seg, testTrace{id: "theirs", at: at})

	for _, id := range []string{"mine", "theirs"} {
		if rec, err := Lookup(context.Background(), at, id); rec == nil || err != nil || rec.ID != id {
			t.Fatalf("Lookup(%q) = %+v, %v", id, rec, err)
		}
	}
}

// Every node's hours are listed, newest hour first and within an hour by node,
// and a page token continues past a node inside an hour as well as past an
// hour.
func TestList_PagesAcrossNodes(t *testing.T) {
	root := enableArchive(t)
	older, newer := hour(t, "2026-09-20T10"), hour(t, "2026-09-20T11")
	writeFile(t, root, older, testTrace{id: "a", at: older.Start().Add(time.Minute)})
	writeNodeFile(t, root, "gw-other", older, testTrace{id: "b", at: older.Start().Add(time.Minute)})
	writeNodeFile(t, root, "gw-other", newer, testTrace{id: "c", at: newer.Start().Add(time.Minute)})

	var got []string
	token := ""
	for range 10 {
		page, next, err := List(time.Time{}, time.Time{}, 1, token)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range page {
			got = append(got, s.Name())
		}
		if token = next; token == "" {
			break
		}
	}
	want := []string{
		"traces-2026-09-20T11Z.gw-other.ndjson.zst",
		"traces-2026-09-20T10Z.gw-test.ndjson.zst",
		"traces-2026-09-20T10Z.gw-other.ndjson.zst",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("listed %v, want %v", got, want)
	}
	d, err := OpenDownload(want[0])
	if err != nil {
		t.Fatalf("another node's hour does not download: %v", err)
	}
	if d.Node != "gw-other" {
		t.Fatalf("download node = %q", d.Node)
	}
	_ = d.Close()
}

// One node's damaged file for an hour does not hide the traces other nodes
// archived for it; the damage is reported only if no node has the trace.
func TestLookup_ADamagedFileDoesNotHideAnotherNodes(t *testing.T) {
	root := enableArchive(t)
	seg := hour(t, "2026-09-20T10")
	at := seg.Start().Add(17 * time.Minute)
	writeFile(t, root, seg, testTrace{id: "mine", at: at})
	writeNodeFile(t, root, "gw-other", seg, testTrace{id: "theirs", at: at})
	if err := os.WriteFile(seg.path(root, testNode), []byte("not a segment"), 0o600); err != nil {
		t.Fatal(err)
	}

	if rec, err := Lookup(context.Background(), at, "theirs"); rec == nil || err != nil {
		t.Fatalf("Lookup = %+v, %v; want gw-other's trace", rec, err)
	}
	if rec, err := Lookup(context.Background(), at, "mine"); rec != nil || err == nil {
		t.Fatalf("Lookup = %+v, %v; want the damage reported", rec, err)
	}
}
