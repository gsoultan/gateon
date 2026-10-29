// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The store's goroutine used to spend six allocations on a browser's trace:
// the operation name, the request URI and that joined to the host, a block
// per header set, and the request block again once its cookie was redacted.
// It spends one on the name and URI together and one on both blocks.
func TestProcessTraceAllocations(t *testing.T) {
	if raceDetector {
		t.Skip("sync.Pool drops items under -race, so allocation counts are not meaningful")
	}
	s := &pathStatsStore{}
	tr := GetTraceRecord()
	got := testing.AllocsPerRun(100, func() {
		fillBenchTrace(tr)
		s.processTrace(tr)
		tr.Reset()
	})
	if got > 2 {
		t.Fatalf("processTrace allocates %v objects per trace, want at most 2", got)
	}
}

// oldDeriveFields is deriveFields as it was before it built one string: the
// reference its output must still equal.
func oldDeriveFields(method, path, uriHost string, u *url.URL) (op, uri, host string) {
	uri = uriHost + u.RequestURI()
	return method + " " + path, uri, requestHost(uri)
}

func checkDeriveFields(t *testing.T, method, path, uriHost string, u url.URL) {
	t.Helper()
	wantOp, wantURI, wantHost := oldDeriveFields(method, path, uriHost, &u)
	tr := &TraceRecord{Method: method, Path: path, deriveOperation: true, uriHost: uriHost, url: u, deriveURI: true}
	tr.deriveFields()
	if tr.OperationName != wantOp || tr.RequestURI != wantURI || tr.Host != wantHost {
		t.Fatalf("deriveFields(%q %q %q %#v) = (%q, %q, %q), want (%q, %q, %q)", method, path, uriHost, u,
			tr.OperationName, tr.RequestURI, tr.Host, wantOp, wantURI, wantHost)
	}
	if tr.deriveOperation || tr.deriveURI || tr.uriHost != "" || tr.url != (url.URL{}) {
		t.Fatalf("deriveFields left its inputs on the record: %+v", tr)
	}

	// Each half alone is what it was too.
	tr = &TraceRecord{Method: method, Path: path, deriveOperation: true, OperationName: "", RequestURI: "kept"}
	tr.deriveFields()
	if tr.OperationName != wantOp || tr.RequestURI != "kept" {
		t.Fatalf("operation only: got (%q, %q), want (%q, %q)", tr.OperationName, tr.RequestURI, wantOp, "kept")
	}
	tr = &TraceRecord{OperationName: "kept", uriHost: uriHost, url: u, deriveURI: true}
	tr.deriveFields()
	if tr.OperationName != "kept" || tr.RequestURI != wantURI || tr.Host != wantHost {
		t.Fatalf("URI only: got (%q, %q, %q), want (%q, %q, %q)", tr.OperationName, tr.RequestURI, tr.Host, "kept", wantURI, wantHost)
	}
}

func TestDeriveFieldsMatchesRequestURI(t *testing.T) {
	for _, tc := range []struct {
		name string
		u    url.URL
	}{
		{"path and query", url.URL{Path: "/bench/items", RawQuery: "page=2"}},
		{"no query", url.URL{Path: "/a/b"}},
		{"empty path", url.URL{}},
		{"empty path with query", url.URL{RawQuery: "q=1"}},
		{"force query", url.URL{Path: "/x", ForceQuery: true}},
		{"path needing escape", url.URL{Path: "/a b/ü"}},
		{"raw path kept", url.URL{Path: "/a/b", RawPath: "/a%2Fb"}},
		{"invalid raw path", url.URL{Path: "/a/b", RawPath: "/zz%2Fb"}},
		{"opaque", url.URL{Scheme: "http", Opaque: "//other.test/p", RawQuery: "a=1"}},
		{"opaque without slashes", url.URL{Scheme: "mailto", Opaque: "user@example.test"}},
		{"query with credential", url.URL{Path: "/cb", RawQuery: "access_token=s3cr3t&x=1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkDeriveFields(t, http.MethodGet, tc.u.Path, "http://gateway.test", tc.u)
			checkDeriveFields(t, "", "", "", tc.u)
		})
	}
}

func FuzzDeriveFields(f *testing.F) {
	f.Add("GET", "/bench/items", "http://gateway.test", "/bench/items", "", "page=2", false, "")
	f.Add("POST", "", "", "/a b", "/a%20b", "", true, "")
	f.Add("GET", "/", "https://h", "", "", "", false, "//x/y")
	f.Fuzz(func(t *testing.T, method, path, uriHost, uPath, rawPath, rawQuery string, force bool, opaque string) {
		u := url.URL{Scheme: "http", Path: uPath, RawPath: rawPath, RawQuery: rawQuery, ForceQuery: force, Opaque: opaque}
		checkDeriveFields(t, method, path, uriHost, u)
	})
}

// redactedTraceHeaders is what processTrace stores for a request's and a
// response's headers.
func redactedTraceHeaders(req, resp http.Header) (string, string) {
	reqPairs, respPairs, _ := snapshotHeaders(nil, req, resp)
	r, w := formatTraceHeaders(reqPairs, respPairs)
	return RedactHeaders(r), RedactHeaders(w)
}

// What is stored must be exactly what was: masking a credential while the
// block is built is not a second redaction policy, only the first step of
// the one RedactHeaders applies.
func TestTraceHeadersRedactAsBefore(t *testing.T) {
	for _, tc := range []struct {
		name      string
		req, resp http.Header
	}{
		{"browser", benchTraceReqHeader, benchTraceRespHeader},
		{"several credentials", http.Header{
			"Authorization":   {"Basic dXNlcjpwYXNz", "Bearer abc.def.ghi"},
			"Cookie":          {"a=1", "b=2"},
			"X-Api-Key":       {"k-123"},
			"X-Session-Token": {"t"},
			"Accept":          {"text/html", "*/*"},
			"X-Empty":         nil,
			"X-Blank":         {""},
		}, http.Header{"Set-Cookie": {"s=1", "t=2"}, "Location": {"/next?token=abc"}}},
		{"URI headers", http.Header{
			"Referer":         {"https://app.test/cb?code=xyz&state=1"},
			"X-Forwarded-Uri": {"/login?password=hunter2"},
		}, nil},
		{"token under a plain name", http.Header{
			"X-Debug": {"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlc2lnbmF0dXJl"},
		}, http.Header{"X-Trace": {"ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"}}},
		{"no response", http.Header{"Accept": {"*/*"}}, nil},
		{"no request", nil, http.Header{"Content-Type": {"text/plain"}}},
		{"neither", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// One snapshot each, so both sides walk the same map order.
			reqPairs, respPairs, _ := snapshotHeaders(nil, tc.req, tc.resp)
			r, w := formatTraceHeaders(reqPairs, respPairs)
			if RedactHeaders(r) != RedactHeaders(reqPairs.format()) || RedactHeaders(w) != RedactHeaders(respPairs.format()) {
				t.Fatalf("stored headers differ from before:\nrequest  %q\nwant     %q\nresponse %q\nwant     %q",
					RedactHeaders(r), RedactHeaders(reqPairs.format()), RedactHeaders(w), RedactHeaders(respPairs.format()))
			}
		})
	}
}

// A credential header's value is masked before RedactHeaders splits the
// block into lines, so a value carrying a line break -- which no parser
// accepts off the wire, but a header map built in code can hold -- is masked
// whole rather than read as a credential line and then a plain one.
func TestTraceHeadersMaskCredentialValueWhole(t *testing.T) {
	req := http.Header{"Cookie": {"a=1\nX-Smuggled: s3cr3t-value"}}
	gotReq, _ := redactedTraceHeaders(req, nil)
	if strings.Contains(gotReq, "s3cr3t-value") {
		t.Fatalf("a credential's value reached the trace: %q", gotReq)
	}
	if !strings.Contains(gotReq, "Cookie: [REDACTED]") {
		t.Fatalf("cookie not recorded as redacted: %q", gotReq)
	}
}

// headerFuzzName keeps a fuzzed name to what a header map from net/http can
// hold, so the comparison with the old output is between equal inputs: the
// two can differ only where a name has a colon or a value a line break, and
// there only in masking more (TestTraceHeadersMaskCredentialValueWhole).
func headerFuzzName(s string) string {
	return strings.Map(func(r rune) rune {
		if r <= ' ' || r == ':' || r >= 0x7f {
			return -1
		}
		return r
	}, s)
}

func FuzzTraceHeadersRedactAsBefore(f *testing.F) {
	f.Add("Cookie", "a=1", "Authorization", "Bearer x", "Referer", "https://h/?token=1", "Set-Cookie", "s=1")
	f.Add("X-Api-Key", "k", "Accept", "*/*", "X-Custom-Token", "abc", "Location", "/p?code=2")
	f.Fuzz(func(t *testing.T, n1, v1, n2, v2, n3, v3, n4, v4 string) {
		clean := func(v string) string { return strings.NewReplacer("\n", "", "\r", "").Replace(v) }
		req, resp := http.Header{}, http.Header{}
		for _, kv := range [][2]string{{n1, v1}, {n2, v2}, {n3, v3}} {
			if name := headerFuzzName(kv[0]); name != "" {
				req[name] = append(req[name], clean(kv[1]))
			}
		}
		if name := headerFuzzName(n4); name != "" {
			resp[name] = append(resp[name], clean(v4), clean(v1))
		}
		reqPairs, respPairs, _ := snapshotHeaders(nil, req, resp)
		r, w := formatTraceHeaders(reqPairs, respPairs)
		if got, want := RedactHeaders(r), RedactHeaders(reqPairs.format()); got != want {
			t.Fatalf("request headers: got %q, want %q", got, want)
		}
		if got, want := RedactHeaders(w), RedactHeaders(respPairs.format()); got != want {
			t.Fatalf("response headers: got %q, want %q", got, want)
		}
	})
}

// Masking while the block is built is only worth doing if it masks as
// RedactHeaders does, so that RedactHeaders finds nothing to change and
// returns the block rather than building it again: the cookie of every
// browser's request, and every value of a header given several.
func TestTraceHeadersMaskedAsRedactHeadersWould(t *testing.T) {
	req := http.Header{
		"Authorization": {"Basic dXNlcjpwYXNz", "Bearer abc.def.ghi"},
		"Cookie":        {"a=1", "b=2"},
		"X-Api-Key":     {"k-123"},
		"Accept":        {"text/html", "*/*"},
	}
	resp := http.Header{"Set-Cookie": {"s=1", "t=2"}, "Content-Type": {"text/html"}}
	reqPairs, respPairs, _ := snapshotHeaders(nil, req, resp)
	r, w := formatTraceHeaders(reqPairs, respPairs)
	if got := RedactHeaders(r); got != r {
		t.Fatalf("request block redacted again:\nbuilt    %q\nredacted %q", r, got)
	}
	if got := RedactHeaders(w); got != w {
		t.Fatalf("response block redacted again:\nbuilt    %q\nredacted %q", w, got)
	}
}
