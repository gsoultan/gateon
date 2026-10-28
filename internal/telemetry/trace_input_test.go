// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The metrics middleware leaves a trace's operation name and request URI to
// the store's goroutine rather than building them per request. They must come
// out as the middleware built them -- "METHOD path", and the host the request
// asked for in front of the URL's request URI -- with the host recorded on its
// own, and the URI redacted, which means derived before redaction runs. A
// recorder that names them keeps its own.
func TestTraceInputDerivesNameAndURIOffTheRequestPath(t *testing.T) {
	withStore(t)
	now := time.Now().UTC()
	u, err := url.Parse("http://ignored.example/orders/7?page=2&access_token=s3cret")
	if err != nil {
		t.Fatal(err)
	}
	RecordRequestTrace(TraceInput{
		ID: "derived-1", ServiceName: "route-a", Timestamp: now, Status: "200",
		Path: "/orders/7", Method: http.MethodGet, SourceIP: "192.0.2.1",
		URIHost: "shop.example:8443", URL: u,
		RequestHeader: http.Header{"Cookie": {"sid=abc"}, "Accept": {"*/*"}},
	})
	// The request's URL changing afterwards reaches nothing: it was copied.
	u.Path, u.RawQuery = "/changed", ""
	RecordRequestTrace(TraceInput{
		ID: "named-1", OperationName: "custom op", ServiceName: "route-a", Timestamp: now, Status: "200",
		Path: "/named", Method: http.MethodPost, SourceIP: "192.0.2.1", RequestURI: "api.example/named",
	})
	FlushTraces()

	got := map[string]*TraceRecord{}
	for _, tr := range GetTracesFiltered(t.Context(), 100, false) {
		got[tr.Path] = tr
	}
	d := got["/orders/7"]
	if d == nil {
		t.Fatalf("derived trace not stored; have %v", got)
	}
	if d.OperationName != "GET /orders/7" {
		t.Errorf("OperationName = %q, want %q", d.OperationName, "GET /orders/7")
	}
	if !strings.HasPrefix(d.RequestURI, "shop.example:8443/orders/7?page=2&access_token=") || strings.Contains(d.RequestURI, "s3cret") {
		t.Errorf("RequestURI = %q, want the host, the path and the query with its token masked", d.RequestURI)
	}
	if d.Host != "shop.example:8443" {
		t.Errorf("Host = %q, want %q", d.Host, "shop.example:8443")
	}
	if strings.Contains(d.RequestHeaders, "sid=abc") || !strings.Contains(d.RequestHeaders, "Accept: */*") {
		t.Errorf("RequestHeaders = %q, want Accept kept and the cookie masked", d.RequestHeaders)
	}

	n := got["/named"]
	if n == nil {
		t.Fatal("named trace not stored")
	}
	if n.OperationName != "custom op" || n.RequestURI != "api.example/named" || n.Host != "api.example" {
		t.Errorf("named trace = %q %q %q, want what its recorder gave", n.OperationName, n.RequestURI, n.Host)
	}
}
