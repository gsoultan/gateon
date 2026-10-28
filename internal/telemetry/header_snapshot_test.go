// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// sortedLines is a formatted header block's lines in order, since a map's
// iteration order -- and so a block's line order -- is not fixed.
func sortedLines(block string) []string {
	lines := strings.Split(block, "\n")
	slices.Sort(lines)
	return lines
}

// A trace's headers used to be cloned into a map per set and formatted with
// FormatHeaders; they are snapshotted as pairs and formatted from those. The
// stored text must be what it was: every header, several values joined in
// their order, and a header with no value still named.
func TestHeaderSnapshotFormatsAsFormatHeaders(t *testing.T) {
	for _, tc := range []struct {
		name      string
		req, resp http.Header
	}{
		{"browser request", http.Header{
			"Accept":       {"text/html", "*/*"},
			"User-Agent":   {"Mozilla/5.0"},
			"Cookie":       {"a=1", "b=2", "c=3"},
			"X-Empty":      nil,
			"X-Zero":       {},
			"X-Blank":      {""},
			"X-Request-Id": {"01JABC"},
		}, http.Header{"Content-Type": {"application/json"}, "Set-Cookie": {"s=1", "t=2"}}},
		{"no response headers", http.Header{"Accept": {"*/*"}}, nil},
		{"no request headers", http.Header{}, http.Header{"Server": {"gateon"}}},
		{"neither", nil, http.Header{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, resp, _ := snapshotHeaders(nil, tc.req, tc.resp)
			if got, want := sortedLines(req.format()), sortedLines(FormatHeaders(CloneHeader(tc.req))); !slices.Equal(got, want) {
				t.Errorf("request block\n got %q\nwant %q", got, want)
			}
			if got, want := sortedLines(resp.format()), sortedLines(FormatHeaders(CloneHeader(tc.resp))); !slices.Equal(got, want) {
				t.Errorf("response block\n got %q\nwant %q", got, want)
			}
		})
	}
}

// The snapshot is one allocation for both sets, and a copy: a header changed
// after the request finished, or an append to one set, reaches neither the
// trace nor the other set.
func TestHeaderSnapshotIsOneAllocationAndACopy(t *testing.T) {
	req := http.Header{"Accept": {"text/html", "*/*"}, "Cookie": {"a=1"}, "User-Agent": {"x"}}
	resp := http.Header{"Content-Type": {"text/plain"}, "Server": {"gateon"}}
	if n := testing.AllocsPerRun(100, func() { snapshotHeaders(nil, req, resp) }); n != 1 {
		t.Fatalf("snapshotHeaders allocated %v times, want 1", n)
	}

	reqPairs, respPairs, _ := snapshotHeaders(nil, req, resp)
	want := respPairs.format()
	req["Cookie"][0] = "changed"
	if strings.Contains(reqPairs.format(), "changed") {
		t.Fatal("the snapshot shares the request's value slice")
	}
	_ = append(reqPairs, "X-Late", "1")
	if got := respPairs.format(); got != want {
		t.Fatalf("appending to the request's pairs wrote into the response's: %q", got)
	}
}

// A pooled record keeps its snapshot's backing array, so the next trace it
// carries snapshots without allocating; Reset empties the array, so a record
// waiting in the pool holds none of a finished request's headers, and does not
// keep one grown past maxPooledHeaderPairs.
func TestTraceRecordReusesItsHeaderSnapshot(t *testing.T) {
	req := http.Header{"Accept": {"text/html", "*/*"}, "Cookie": {"sid=secret"}, "User-Agent": {"x"}}
	resp := http.Header{"Content-Type": {"text/plain"}, "Server": {"gateon"}}

	tr := &TraceRecord{}
	tr.rawReqHeader, tr.rawRespHeader, tr.headerBuf = snapshotHeaders(tr.headerBuf, req, resp)
	tr.Reset()
	if cap(tr.headerBuf) == 0 {
		t.Fatal("Reset dropped the snapshot buffer")
	}
	for _, v := range tr.headerBuf[:cap(tr.headerBuf)] {
		if v != "" {
			t.Fatalf("a reset record still holds %q", v)
		}
	}
	if tr.rawReqHeader != nil || tr.rawRespHeader != nil {
		t.Fatal("Reset left the snapshot's pairs set")
	}

	if n := testing.AllocsPerRun(100, func() {
		tr.rawReqHeader, tr.rawRespHeader, tr.headerBuf = snapshotHeaders(tr.headerBuf, req, resp)
		tr.Reset()
	}); n != 0 {
		t.Fatalf("a reused record's snapshot allocated %v times, want 0", n)
	}
	reqPairs, _, _ := snapshotHeaders(tr.headerBuf, req, resp)
	if got, want := sortedLines(reqPairs.format()), sortedLines(FormatHeaders(CloneHeader(req))); !slices.Equal(got, want) {
		t.Fatalf("a reused buffer's block\n got %q\nwant %q", got, want)
	}

	big := http.Header{}
	for i := range maxPooledHeaderPairs {
		big["X-H"+strconv.Itoa(i)] = []string{"v"}
	}
	tr.rawReqHeader, tr.rawRespHeader, tr.headerBuf = snapshotHeaders(tr.headerBuf, big, nil)
	tr.Reset()
	if cap(tr.headerBuf) != 0 {
		t.Fatalf("Reset kept a %d-slot buffer, past the %d bound", cap(tr.headerBuf), maxPooledHeaderPairs)
	}
}

// RedactHeaders hands back a block it did not change rather than a copy of it:
// most blocks -- nearly every response's -- carry no credential, and the copy
// was one of a trace's allocations. A block it does change is still masked.
func TestRedactHeadersKeepsAnUnchangedBlock(t *testing.T) {
	clean := "Content-Type: application/json\nServer: gateon\n"
	if got := RedactHeaders(clean); got != clean {
		t.Fatalf("a credential-free block changed: %q", got)
	}
	if n := testing.AllocsPerRun(100, func() { _ = RedactHeaders(clean) }); n != 0 {
		t.Fatalf("redacting a credential-free block allocated %v times, want 0", n)
	}
	if got := RedactHeaders("Cookie: sid=secret\nAccept: */*\n"); strings.Contains(got, "secret") {
		t.Fatalf("a cookie survived redaction: %q", got)
	}
}
