// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/tracearchive"
)

// archivedHour stores traces -- one, unless paths are given -- archives their
// hour and returns it.
func archivedHour(t *testing.T, paths ...string) tracearchive.Segment {
	t.Helper()
	t.Setenv("GATEON_PROFILE", "standard")
	dir := t.TempDir()
	t.Setenv("GATEON_TRACE_DIR", filepath.Join(dir, "pebble"))
	t.Setenv(tracearchive.EnvDir, filepath.Join(dir, "archive"))
	t.Setenv(tracearchive.EnvEnabled, "true")
	t.Setenv(tracearchive.EnvNodeName, archiveNode)
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(dir, "telemetry.db"), 7); err != nil {
		t.Fatalf("InitPathStatsStore: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })

	at := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Hour).Add(time.Minute)
	if len(paths) == 0 {
		paths = []string{"/x"}
	}
	for i, p := range paths {
		id := "t-1"
		if i > 0 {
			id = fmt.Sprintf("t-%d", i+1)
		}
		telemetry.RecordTrace(id, "GET "+p, "svc", "r", 1, at.Add(time.Duration(i)*time.Millisecond), "200", p,
			"192.0.2.1", "", "", "", "GET", "", p, "", "", nil, nil, "none", 0, 0, 0, 0, 0)
	}
	telemetry.FlushTraces()
	(&tracearchive.Archiver{}).ArchiveNow(context.Background())
	return tracearchive.SegmentAt(at)
}

// archiveNode is the name the tests' gateway archives under.
const archiveNode = "gw-test"

// archiveName is the name an hour this gateway archived downloads by.
func archiveName(seg tracearchive.Segment) string { return seg.FileName(archiveNode) }

// archivePath is where that hour's file is on disk.
func archivePath(seg tracearchive.Segment) string {
	return filepath.Join(os.Getenv(tracearchive.EnvDir), archiveNode, seg.Start().Format("2006/01/02"), archiveName(seg))
}

func download(t *testing.T, path string, claims *auth.Claims) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	registerTracesHandlers(mux, &api.ApiService{})
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if claims != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey, claims))
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// An archived hour downloads as an attachment the browser may not sniff: it
// is traffic from strangers, and rendered inline it would run what they sent.
func TestTraceArchiveDownload_SendsAnAttachmentNeverAPage(t *testing.T) {
	seg := archivedHour(t)
	viewer := &auth.Claims{ID: "v", Username: "viewer", Role: auth.RoleViewer}

	raw := download(t, "/v1/traces/archives/"+archiveName(seg), viewer)
	if raw.Code != http.StatusOK {
		t.Fatalf("compressed download: %d %s", raw.Code, raw.Body.String())
	}
	onDisk, err := os.ReadFile(archivePath(seg))
	if err != nil {
		t.Fatal(err)
	}
	if raw.Body.String() != string(onDisk) {
		t.Fatal("the compressed download is not the archived file")
	}
	for name, want := range map[string]string{
		"Content-Type":           "application/zstd",
		"Content-Disposition":    `attachment; filename=` + archiveName(seg),
		"X-Content-Type-Options": "nosniff",
		"Cache-Control":          "private, no-store",
	} {
		if got := raw.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	plain := download(t, "/v1/traces/archives/"+archiveName(seg)+"?format=ndjson", viewer)
	if plain.Code != http.StatusOK || !strings.Contains(plain.Body.String(), `"id":"t-1"`) {
		t.Fatalf("NDJSON download: %d %q", plain.Code, plain.Body.String())
	}
	if got := plain.Header().Get("Content-Disposition"); got != "attachment; filename="+strings.TrimSuffix(archiveName(seg), ".zst") {
		t.Errorf("NDJSON Content-Disposition = %q", got)
	}
	if plain.Header().Get("X-Content-Type-Options") != "nosniff" || plain.Header().Get("Content-Type") != "application/x-ndjson" ||
		plain.Header().Get("Cache-Control") != "private, no-store" {
		t.Errorf("NDJSON headers = %v", plain.Header())
	}
}

func TestTraceArchiveDownload_RefusesWhatItShould(t *testing.T) {
	seg := archivedHour(t)
	admin := &auth.Claims{ID: "a", Username: "admin", Role: auth.RoleAdmin}
	for name, tc := range map[string]struct {
		path   string
		claims *auth.Claims
		want   int
	}{
		"a role without diagnostics": {"/v1/traces/archives/" + archiveName(seg), &auth.Claims{ID: "g", Role: "guest"}, http.StatusForbidden},
		"not a segment name":         {"/v1/traces/archives/passwd", admin, http.StatusBadRequest},
		"an encoded traversal":       {"/v1/traces/archives/..%2F..%2Fgateon.db", admin, http.StatusBadRequest},
		"a node that is a path":      {"/v1/traces/archives/traces-2026-09-26T14Z...%2F..%2Fetc.ndjson.zst", admin, http.StatusBadRequest},
		"an hour not archived":       {"/v1/traces/archives/" + archiveName(seg.Next()), admin, http.StatusNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			if rr := download(t, tc.path, tc.claims); rr.Code != tc.want {
				t.Fatalf("status %d (%s), want %d", rr.Code, rr.Body.String(), tc.want)
			}
		})
	}
}

func TestTraceArchiveDownload_BusyIsAnAnswerToRetry(t *testing.T) {
	seg := archivedHour(t)
	var held []*tracearchive.Download
	for {
		d, err := tracearchive.OpenDownload(archiveName(seg))
		if err != nil {
			break
		}
		held = append(held, d)
	}
	defer func() {
		for _, d := range held {
			_ = d.Close()
		}
	}()
	rr := download(t, "/v1/traces/archives/"+archiveName(seg), nil)
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("with every slot taken: %d, Retry-After %q; want 503 with a Retry-After", rr.Code, rr.Header().Get("Retry-After"))
	}
}

// damageFrame flips a byte inside the file's last data frame, just before its
// index, whose offset the header gives.
func damageFrame(t *testing.T, seg tracearchive.Segment) {
	t.Helper()
	path := archivePath(seg)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var head struct {
		IndexAt int `json:"indexAt"`
	}
	if err := json.Unmarshal(bytes.TrimRight(raw[8:512], " "), &head); err != nil {
		t.Fatalf("header: %v", err)
	}
	raw[head.IndexAt-20] ^= 0xff
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A decompressed download that fails before anything is sent says so; one
// that fails after part of the file has gone out must not end as if it were
// whole, or the client keeps a short file that looks complete.
func TestTraceArchiveDownload_ADamagedFileIsNeverSentAsWhole(t *testing.T) {
	t.Run("before anything is sent", func(t *testing.T) {
		seg := archivedHour(t)
		damageFrame(t, seg)
		if rr := download(t, "/v1/traces/archives/"+archiveName(seg)+"?format=ndjson", nil); rr.Code != http.StatusInternalServerError {
			t.Fatalf("status %d, want 500", rr.Code)
		}
	})
	t.Run("part-way through", func(t *testing.T) {
		seg := archivedHour(t, largeHour...)
		damageFrame(t, seg)
		defer func() {
			if r := recover(); r != http.ErrAbortHandler { //nolint:errorlint // a panic value, compared as net/http does
				t.Fatalf("recovered %v, want http.ErrAbortHandler", r)
			}
		}()
		rr := download(t, "/v1/traces/archives/"+archiveName(seg)+"?format=ndjson", nil)
		t.Fatalf("the download ended normally with %d bytes sent; it must be aborted", rr.Body.Len())
	})
}

// largeHour is enough traces for two frames of NDJSON.
var largeHour = func() []string {
	ids := make([]string, 1200)
	for i := range ids {
		ids[i] = fmt.Sprintf("big-%04d-%s", i, strings.Repeat("p", 1000))
	}
	return ids
}()
