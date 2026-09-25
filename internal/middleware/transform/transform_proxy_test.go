// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

// behindTheGatewaysProxy serves backend through a reverse proxy configured as
// pkg/proxy configures it -- FlushInterval -1, a flush after every write --
// with the transform middleware in front.
func behindTheGatewaysProxy(t *testing.T, cfg BodyTransformConfig, backend http.HandlerFunc) *httptest.Server {
	t.Helper()
	origin := httptest.NewServer(backend)
	t.Cleanup(origin.Close)
	u, _ := url.Parse(origin.URL)
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.FlushInterval = -1
	srv := httptest.NewServer(BodyTransform(cfg)(rp))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, srv *httptest.Server, acceptEncoding string) (string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if acceptEncoding != "" {
		req.Header.Set("Accept-Encoding", acceptEncoding)
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), resp.Header
}

// TestResponseTransformAppliesBehindTheProxy: the gateway's reverse proxy
// flushes after every write, and the transform writer took any flush as a
// stream it must not hold back -- so behind the proxy no response was ever
// rewritten. The content-type filter was also checked against the request, so
// with a filter set, a GET (which has no Content-Type) was never rewritten
// either.
func TestResponseTransformAppliesBehindTheProxy(t *testing.T) {
	srv := behindTheGatewaysProxy(t,
		BodyTransformConfig{ResponseSearch: "internal.example", ResponseReplace: "api.example.com", ContentTypeFilter: "application/json"},
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"next":"https://`))
			_, _ = w.Write([]byte(`internal.example/page/2"}`))
		})
	if body, _ := get(t, srv, ""); body != `{"next":"https://api.example.com/page/2"}` {
		t.Fatalf("body = %s, want the rewritten link", body)
	}
}

// TestResponseTransformAsksTheBackendForPlainBytes: the client's
// Accept-Encoding went through to the backend, which compressed its answer,
// and a search for "internal.example" does not occur in gzip bytes -- the
// rewrite silently did nothing, or could corrupt the stream if it matched.
func TestResponseTransformAsksTheBackendForPlainBytes(t *testing.T) {
	srv := behindTheGatewaysProxy(t,
		BodyTransformConfig{ResponseSearch: "internal.example", ResponseReplace: "api.example.com"},
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			body := `<a href="https://internal.example/">home</a>`
			if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				w.Header().Set("Content-Encoding", "gzip")
				zw := gzip.NewWriter(w)
				_, _ = zw.Write([]byte(body))
				_ = zw.Close()
				return
			}
			_, _ = w.Write([]byte(body))
		})
	body, h := get(t, srv, "gzip")
	if h.Get("Content-Encoding") != "" || body != `<a href="https://api.example.com/">home</a>` {
		t.Fatalf("Content-Encoding %q body %q, want the plain rewritten page", h.Get("Content-Encoding"), body)
	}
}

// TestResponseTransformLeavesOtherTypesAndStreams: the filter now reads the
// response, and a stream is still passed through as it comes.
func TestResponseTransformLeavesOtherTypesAndStreams(t *testing.T) {
	for _, tc := range []struct{ ct, filter string }{
		{"text/html", "application/json"},
		{"text/event-stream", "application/json"},
		{"text/event-stream", ""}, // a stream, with nothing filtering it out
	} {
		ct := tc.ct
		srv := behindTheGatewaysProxy(t,
			BodyTransformConfig{ResponseSearch: "x", ResponseReplace: "y", ContentTypeFilter: tc.filter},
			func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", ct)
				_, _ = w.Write([]byte("xxx"))
			})
		if body, _ := get(t, srv, ""); body != "xxx" {
			t.Errorf("%s response under filter %q was rewritten: %q", ct, tc.filter, body)
		}
	}
}

// TestResponseTransformNeverRewritesEncodedBytes: with Accept-Encoding
// removed, Go's transport asks for gzip itself and decodes it, so a backend
// that gzips regardless still arrives as plain bytes. One that sends another
// encoding anyway -- brotli here -- arrives encoded, and must go through
// untouched: a search that happened to match inside compressed bytes would
// corrupt the stream.
func TestResponseTransformNeverRewritesEncodedBytes(t *testing.T) {
	const encoded = "\x8b\x05\x80plain page and search-me inside\x03"
	srv := behindTheGatewaysProxy(t,
		BodyTransformConfig{ResponseSearch: "search-me", ResponseReplace: "XX"},
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "br")
			_, _ = w.Write([]byte(encoded))
		})
	// An explicit Accept-Encoding stops Go's client transport from decoding
	// anything itself, which would hide what went over the wire.
	if body, _ := get(t, srv, "identity"); body != encoded {
		t.Fatalf("encoded body was altered: %q", body)
	}
}
