// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ui

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

// The web app manifest went out as text/plain: Go's mime table has no entry
// for .webmanifest, so the file server sniffed the type from the bytes. Root
// cause: the handler only ever asked mime.TypeByExtension.
func TestTheWebAppManifestIsServedAsManifestJSON(t *testing.T) {
	const manifest = `{"name":"Gateon Dashboard","start_url":"/"}`
	for _, tc := range []struct {
		name   string
		files  fstest.MapFS
		accept string
	}{
		{"plain", fstest.MapFS{
			"dist/index.html":           {Data: []byte("<html></html>")},
			"dist/manifest.webmanifest": {Data: []byte(manifest)},
		}, ""},
		{"precompressed", fstest.MapFS{
			"dist/index.html":              {Data: []byte("<html></html>")},
			"dist/manifest.webmanifest":    {Data: []byte(manifest)},
			"dist/manifest.webmanifest.br": {Data: []byte("BROTLI")},
		}, "br"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/manifest.webmanifest", nil)
			if tc.accept != "" {
				req.Header.Set("Accept-Encoding", tc.accept)
			}
			StaticHandler(tc.files, "dist").ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/manifest+json" {
				t.Errorf("Content-Type %q, want application/manifest+json", got)
			}
		})
	}
}
