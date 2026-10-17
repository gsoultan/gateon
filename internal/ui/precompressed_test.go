// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ui

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gsoultan/gateon/internal/middleware/traffic"
)

// The dashboard build ships every asset with .br and .gz beside it, and the
// handler served only the plain file. The management chain's compress
// middleware then brotli-encoded each asset on the fly, for unauthenticated
// clients, at about 11 MiB of live heap per encoder: 200 concurrent requests
// for the largest bundle held 2.2 GiB. Root cause: the static handler never
// looked for the precompressed variants the build had already produced.

const plainJS = "console.log('plain asset, long enough to be worth compressing');"

func precompressedFS() fstest.MapFS {
	return fstest.MapFS{
		"dist/index.html":         {Data: []byte("<html></html>")},
		"dist/assets/app.js":      {Data: []byte(strings.Repeat(plainJS, 64))},
		"dist/assets/app.js.br":   {Data: []byte("BROTLI-BYTES")},
		"dist/assets/app.js.gz":   {Data: []byte("GZIP-BYTES")},
		"dist/assets/only.css":    {Data: []byte(strings.Repeat("a{color:red}", 200))},
		"dist/assets/only.css.gz": {Data: []byte("GZIP-CSS")},
	}
}

func TestAUIAssetIsServedFromItsPrecompressedVariant(t *testing.T) {
	// Behind the same compress middleware the management chain puts in front
	// of the UI, so a second encoding on top of the precompressed one shows.
	h := traffic.Compress()(StaticHandler(precompressedFS(), "dist"))

	for _, tc := range []struct {
		path, accept, wantEncoding, wantBody string
	}{
		{"/assets/app.js", "gzip, deflate, br", "br", "BROTLI-BYTES"},
		{"/assets/app.js", "gzip", "gzip", "GZIP-BYTES"},
		{"/assets/app.js", "br;q=0, gzip", "gzip", "GZIP-BYTES"},
		{"/assets/only.css", "br, gzip", "gzip", "GZIP-CSS"},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Header.Set("Accept-Encoding", tc.accept)
		h.ServeHTTP(rec, req)

		name := tc.path + " [" + tc.accept + "]"
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", name, rec.Code)
		}
		if got := rec.Header().Get("Content-Encoding"); got != tc.wantEncoding {
			t.Errorf("%s: Content-Encoding %q, want %q", name, got, tc.wantEncoding)
		}
		if got := rec.Body.String(); got != tc.wantBody {
			t.Errorf("%s: body is not the precompressed file (%d bytes)", name, len(got))
		}
		if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(len(tc.wantBody)) {
			t.Errorf("%s: Content-Length %q, want %d", name, got, len(tc.wantBody))
		}
		if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
			t.Errorf("%s: no Vary: Accept-Encoding", name)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "css") && !strings.Contains(ct, "javascript") {
			t.Errorf("%s: Content-Type %q is not the asset's own", name, ct)
		}
	}
}

func TestAUIAssetIsServedPlainToAClientThatAcceptsNoEncoding(t *testing.T) {
	h := StaticHandler(precompressedFS(), "dist")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
	if rec.Header().Get("Content-Encoding") != "" || rec.Body.String() != strings.Repeat(plainJS, 64) {
		t.Fatalf("a client offering no encoding got Content-Encoding %q and %d bytes",
			rec.Header().Get("Content-Encoding"), rec.Body.Len())
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
		t.Errorf("the identity answer has no Vary: Accept-Encoding, so a cache could hand it the br one")
	}
}
