// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestSummaryTracesCarryTheRequestHost: the anomaly analysis reads summary
// traces, which leave RequestURI -- where the host was only ever recorded, in
// front of the path -- undecoded. The unlisted-route fix needs the host to
// point a new route at the service that already serves it, so the host is
// recorded on its own and read back by the summary decoder.
func TestSummaryTracesCarryTheRequestHost(t *testing.T) {
	withStore(t)

	now := time.Now().UTC()
	RecordTrace("trace-host-1", "GET /new-page", "gateon-websecure", "", 3, now,
		"404", "/new-page", "10.0.0.7", "", "", "curl/8", http.MethodGet,
		"", "app.example.com:8443/new-page?q=1", "", "", nil, nil, "", 0, 0, 0, 0, 0)
	// A debug session records through the detailed variant.
	RecordTraceDetailed("trace-host-2", "GET /debugged", "gateon-websecure", "", 3, now,
		"404", "/debugged", "10.0.0.7", "", "", "curl/8", http.MethodGet,
		"", "api.example.com/debugged", "", "", nil, "", nil, "", "", 0, 0, 0, 0, 0)
	FlushTraces()

	want := map[string]string{"/new-page": "app.example.com:8443", "/debugged": "api.example.com"}
	for _, tr := range GetTracesFiltered(t.Context(), 100, true) {
		if host, ok := want[tr.Path]; ok {
			if tr.Host != host {
				t.Errorf("summary trace for %s: Host = %q, want %q", tr.Path, tr.Host, host)
			}
			delete(want, tr.Path)
		}
	}
	if len(want) > 0 {
		t.Fatalf("recorded traces not found among the summary traces: %v", want)
	}
}

// TestTraceSummaryWithoutAHostStillDecodes: traces written before the field
// existed are in every store being upgraded; they must decode, with no host.
func TestTraceSummaryWithoutAHostStillDecodes(t *testing.T) {
	var tr TraceRecord
	old := `{"id":"t1","serviceName":"gateon-http","path":"/x","sourceIp":"10.0.0.1","requestUri":"localhost/x"}`
	if err := UnmarshalTraceSummary([]byte(old), &tr); err != nil {
		t.Fatalf("decode a trace written before host was recorded: %v", err)
	}
	if tr.Host != "" || tr.Path != "/x" {
		t.Errorf("Host = %q, Path = %q; want no host and the path", tr.Host, tr.Path)
	}
}

// TestRequestHostIsTheFrontOfTheRecordedURI pins the format the metrics
// middleware records (origHost + r.URL.RequestURI()) and the bound on it.
func TestRequestHostIsTheFrontOfTheRecordedURI(t *testing.T) {
	for _, tc := range []struct{ uri, want string }{
		{"localhost:8081/unlisted?x=1", "localhost:8081"},
		{"[::1]:8443/x", "[::1]:8443"},
		{"example.com/", "example.com"},
		{"/no-host", ""},
		{"example.com*", ""},
		{"", ""},
		{strings.Repeat("a", maxRecordedHostLen+1) + "/x", ""},
		{strings.Repeat("a", maxRecordedHostLen) + "/x", strings.Repeat("a", maxRecordedHostLen)},
	} {
		if got := requestHost(tc.uri); got != tc.want {
			t.Errorf("requestHost(%.40q) = %.40q, want %.40q", tc.uri, got, tc.want)
		}
	}
	uri := "app.example.com:8443/" + strings.Repeat("p", 4096)
	if n := testing.AllocsPerRun(100, func() { _ = requestHost(uri) }); n != 0 {
		t.Errorf("requestHost allocates %.0f times per call; it runs on every recorded request", n)
	}
}
