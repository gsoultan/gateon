// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// TestAMissingAssetsPathIsNotEchoedBack: the 404 for a missing asset gets the
// Content-Type of the extension that was asked for -- so a browser reports a
// clean 404 for a script rather than a MIME mismatch -- and it used to echo
// the requested path in its body. Any path under assets/ is an asset whatever
// its extension, so a link to "/assets/<markup>.html" had the dashboard's own
// origin serve that markup as HTML.
func TestAMissingAssetsPathIsNotEchoedBack(t *testing.T) {
	h := StaticHandler(fstest.MapFS{"dist/index.html": {Data: []byte("<html></html>")}}, "dist")
	for _, p := range []string{
		"/assets/%3Cb%3Emarker%3C%2Fb%3E.html",
		"/assets/%3Cb%3Emarker%3C%2Fb%3E.js",
		"/static/%3Cb%3Emarker%3C%2Fb%3E.css",
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, p, nil))
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", p, rr.Code)
		}
		if strings.Contains(rr.Body.String(), "marker") {
			t.Errorf("%s: the 404 echoed the requested path, served as %q: %q",
				p, rr.Header().Get("Content-Type"), rr.Body.String())
		}
	}
}
