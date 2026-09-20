// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// An origin that sends 103 Early Hints before its real status must not have
// that real status swallowed by the compressor's write-once header guard.
func TestCompressForwardsInformationalThenFinalStatus(t *testing.T) {
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</app.css>; rel=preload; as=style")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(bytes.Repeat([]byte("x"), 4096))
	})
	srv := httptest.NewServer(CompressWithConfig(CompressConfig{})(origin))
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("client saw status %d, want 404: the 1xx was recorded as the final status", resp.StatusCode)
	}
}
