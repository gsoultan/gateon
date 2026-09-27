// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"net/http"
	"testing"
	"time"
)

// TestSummaryTracesFlagARequestThatPresentedAPassword: the brute-force check
// counts a refused GET only when it presented a password, and it reads summary
// traces, which carry no headers. So the recording path decides from the
// Authorization scheme and the summary decoder must hand the answer back.
// Bearer is a token the server issued, and repeating a stale one is a session
// that ended; it must not be flagged.
func TestSummaryTracesFlagARequestThatPresentedAPassword(t *testing.T) {
	withStore(t)

	cases := map[string]struct {
		header map[string][]string
		want   bool
	}{
		"/basic":         {map[string][]string{"Authorization": {"Basic YWRtaW46aHVudGVyMg=="}}, true},
		"/basic-lower":   {map[string][]string{"Authorization": {"basic YWRtaW46aHVudGVyMg=="}}, true},
		"/digest":        {map[string][]string{"Authorization": {`Digest username="admin", response="6629fae4"`}}, true},
		"/bearer":        {map[string][]string{"Authorization": {"Bearer eyJhbGciOiJIUzI1NiJ9.e30.x"}}, false},
		"/negotiate":     {map[string][]string{"Authorization": {"Negotiate YIIGhgYGKwYBBQUCoIIGejCCBnagMDAu"}}, false},
		"/basic-no-cred": {map[string][]string{"Authorization": {"Basic "}}, false},
		"/basicish":      {map[string][]string{"Authorization": {"Basicx YWRtaW46aHVudGVyMg=="}}, false},
		"/cookie":        {map[string][]string{"Cookie": {"session=expired"}}, false},
		"/none":          {nil, false},
	}
	now := time.Now().UTC()
	for path, tc := range cases {
		RecordTrace("pw-"+path, "GET "+path, "gateon-web", "", 3, now, "401", path, "203.0.113.9", "", "",
			"curl/8", http.MethodGet, "", "app.example.com"+path, "", "", tc.header, nil, "", 0, 0, 0, 0, 0)
	}
	// The debugger records through the detailed variant; it must flag too.
	RecordTraceDetailed("pw-detailed", "GET /detailed", "gateon-web", "", 3, now, "401", "/detailed", "203.0.113.9",
		"", "", "curl/8", http.MethodGet, "", "app.example.com/detailed", "", "",
		map[string][]string{"Authorization": {"Basic YWRtaW46aHVudGVyMg=="}}, "", nil, "", "", 0, 0, 0, 0, 0)
	cases["/detailed"] = struct {
		header map[string][]string
		want   bool
	}{want: true}
	FlushTraces()

	seen := 0
	for _, tr := range GetTracesFiltered(t.Context(), 100, true) {
		tc, ok := cases[tr.Path]
		if !ok {
			continue
		}
		seen++
		if tr.PasswordAuth != tc.want {
			t.Errorf("summary trace for %s: PasswordAuth = %v, want %v", tr.Path, tr.PasswordAuth, tc.want)
		}
	}
	if seen != len(cases) {
		t.Fatalf("found %d of the %d recorded traces among the summaries", seen, len(cases))
	}
}

// TestTraceSummaryWithoutThePasswordFlagDecodesAsNoPassword: every store being
// upgraded holds traces written before the flag existed.
func TestTraceSummaryWithoutThePasswordFlagDecodesAsNoPassword(t *testing.T) {
	tr := TraceRecord{PasswordAuth: true} // a pooled record's leftovers must not survive
	old := `{"id":"t1","path":"/x","status":"401","sourceIp":"203.0.113.9","method":"GET"}`
	if err := UnmarshalTraceSummary([]byte(old), &tr); err != nil {
		t.Fatalf("decode a trace written before the flag: %v", err)
	}
	if tr.PasswordAuth {
		t.Error("a trace with no passwordAuth field decoded as having presented a password")
	}
}

// TestPresentsPasswordAllocatesNothing: it runs for every recorded request.
func TestPresentsPasswordAllocatesNothing(t *testing.T) {
	h := map[string][]string{"Authorization": {"Digest username=\"admin\", response=\"6629fae4\""}}
	if n := testing.AllocsPerRun(100, func() { _ = presentsPassword(h) }); n != 0 {
		t.Errorf("presentsPassword allocates %.0f times per call", n)
	}
}
