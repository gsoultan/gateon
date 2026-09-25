// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func compressServing(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := CompressWithConfig(CompressConfig{MinResponseBodyBytes: 1024})(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(body))
		}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestCompressLeavesBodiesUnderTheMinimumAlone: a response that ended below
// min_response_body_bytes was still undecided when the writer closed, and the
// close path compressed it anyway -- the minimum decided nothing, and a
// 100-byte page came back as gzip framing around 100 bytes.
func TestCompressLeavesBodiesUnderTheMinimumAlone(t *testing.T) {
	small := strings.Repeat("a", 100)
	rec := compressServing(t, small)
	if enc := rec.Header().Get("Content-Encoding"); enc != "" {
		t.Fatalf("100-byte body under a 1024-byte minimum came back %s-encoded", enc)
	}
	if rec.Body.String() != small {
		t.Fatalf("body = %q, want it untouched", rec.Body)
	}

	if enc := compressServing(t, strings.Repeat("a", 2048)).Header().Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("2048-byte body: Content-Encoding %q, want gzip", enc)
	}
}

// TestCompressMinimumHoldsBehindTheProxy: pkg/proxy's reverse proxy flushes
// after every write, and a flush decided compression before the size was
// known -- so behind the proxy the minimum was skipped again. A response that
// declares its length is decided on that length when its header is written.
func TestCompressMinimumHoldsBehindTheProxy(t *testing.T) {
	for _, tc := range []struct {
		size int
		want string
	}{{100, ""}, {4096, "gzip"}} {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Length", strconv.Itoa(tc.size))
			_, _ = w.Write([]byte(strings.Repeat("a", tc.size)))
		}))
		u, _ := url.Parse(origin.URL)
		rp := httputil.NewSingleHostReverseProxy(u)
		rp.FlushInterval = -1
		h := CompressWithConfig(CompressConfig{MinResponseBodyBytes: 1024})(rp)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		origin.Close()
		if got := rec.Header().Get("Content-Encoding"); got != tc.want {
			t.Errorf("%d-byte body behind the proxy: Content-Encoding %q, want %q", tc.size, got, tc.want)
		}
	}
}
