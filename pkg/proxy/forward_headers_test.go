// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// The forwarding headers are set on every proxied request, and Header.Set
// allocated a one-element slice for each: five allocations a request. They
// are now cut from one array. The values the origin sees must be the same,
// an existing X-Forwarded-For must be extended rather than replaced, and
// X-Forwarded-Ssl must appear only for TLS.
func TestRewriteRequestSetsTheForwardingHeadersFromOneArray(t *testing.T) {
	rs := &request.RequestState{ClientRemoteAddr: "198.51.100.7"}
	in := httptest.NewRequest(http.MethodGet, "http://gateway.example/path?q=1", nil)
	in.RemoteAddr = "198.51.100.7:40000"
	in.Header.Set("X-Forwarded-For", "203.0.113.9")
	in = in.WithContext(context.WithValue(in.Context(), request.RequestStateContextKey{}, rs))
	state := newTargetStateWithProxy("http://backend:8080", 1, false, 0)
	h := &ProxyHandler{}

	pr := &httputil.ProxyRequest{In: in, Out: in.Clone(in.Context())}
	h.rewriteRequest(pr, state)

	want := map[string]string{
		"X-Real-Ip":         "198.51.100.7",
		"X-Forwarded-For":   "203.0.113.9, 198.51.100.7",
		"X-Forwarded-Host":  "gateway.example",
		"X-Forwarded-Proto": "http",
	}
	for name, value := range want {
		if got := pr.Out.Header.Get(name); got != value {
			t.Fatalf("%s = %q, want %q", name, got, value)
		}
	}
	if _, ok := pr.Out.Header["X-Forwarded-Ssl"]; ok {
		t.Fatal("X-Forwarded-Ssl set on a plaintext request")
	}
	if pr.Out.URL.RawQuery != "q=1" || pr.Out.URL.Host != "backend:8080" {
		t.Fatalf("out URL = %s", pr.Out.URL)
	}

	// Appending to one header downstream must not overwrite its neighbour in
	// the shared array.
	pr.Out.Header.Add("X-Real-Ip", "extra")
	if got := pr.Out.Header.Get("X-Forwarded-For"); got != "203.0.113.9, 198.51.100.7" {
		t.Fatalf("appending to X-Real-Ip changed X-Forwarded-For to %q", got)
	}

	// The whole rewrite, forwarding headers and the gateway's JA4 included,
	// should cost a handful of allocations: the joined path, the extended
	// X-Forwarded-For, the array, the JA4 value.
	n := testing.AllocsPerRun(200, func() {
		pr := &httputil.ProxyRequest{In: in, Out: in.Clone(in.Context())}
		h.rewriteRequest(pr, state)
	})
	base := testing.AllocsPerRun(200, func() { in.Clone(in.Context()) })
	if n-base > 6 {
		t.Fatalf("rewriteRequest allocated %v times beyond cloning the request, want at most 6", n-base)
	}
}
