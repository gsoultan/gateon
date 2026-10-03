// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// TestCompressMaxBufferBytesTakesEffect: the dashboard's "Max Buffer" for the
// compress middleware was read by the factory into CompressConfig and looked
// at by nothing, so every response was compressed whatever it said. Found by
// the config-fed dead-field check (scripts/checkconfig, ADR 0048). Built
// through the factory, with the key the dashboard writes.
func TestCompressMaxBufferBytesTakesEffect(t *testing.T) {
	for _, tc := range []struct {
		max  string
		want string
	}{{"4096", ""}, {"8192", "gzip"}} {
		mw, err := NewCompress(map[string]string{"max_buffer_bytes": tc.max})
		if err != nil {
			t.Fatal(err)
		}
		body := strings.Repeat("a", 5000)
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_, _ = w.Write([]byte(body))
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Content-Encoding"); got != tc.want {
			t.Errorf("max_buffer_bytes=%s, 5000-byte body: Content-Encoding %q, want %q", tc.max, got, tc.want)
		}
	}
}
