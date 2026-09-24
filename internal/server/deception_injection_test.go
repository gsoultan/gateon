// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The deception middleware injects invisible trap links into HTML responses.
// Its response writer returned the length of the enlarged buffer from Write,
// which breaks io.Writer's contract (n must not exceed len(p)).
// httputil.ReverseProxy reads that as io.ErrShortWrite and, under a real
// server, aborts the handler -- so every proxied HTML page on a route with link
// injection reached the client as a dropped connection. Content-Length was
// also dropped only for 200, so an HTML error page overran its declared length.
//
// A real server is required: the proxy only aborts when it can see one in the
// request context, so a ResponseRecorder shows a healthy page either way.
func TestDeceptionInjectionServesProxiedHTMLPages(t *testing.T) {
	const page = "<html><body><p>hello</p></body></html>"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(page)))
		if r.URL.Path == "/missing" {
			w.WriteHeader(http.StatusNotFound)
		}
		_, _ = io.WriteString(w, page)
	}))
	defer backend.Close()

	gw := httptest.NewServer(routeIdentityGateway(t, backend.URL,
		&gateonv1.Route{Id: "decoy-route", Rule: "PathPrefix(`/`)", Type: "http"},
		&gateonv1.Middleware{Id: "decoy", Name: "decoy", Type: "deception",
			Config: map[string]string{"invisible_link_paths": "/trap-link"}}))
	defer gw.Close()

	for path, wantStatus := range map[string]int{"/home": http.StatusOK, "/missing": http.StatusNotFound} {
		resp, err := http.Get(gw.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v -- the proxy aborted the response", path, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("GET %s: reading body: %v -- the response was cut off", path, err)
		}
		if resp.StatusCode != wantStatus {
			t.Errorf("GET %s: status %d, want %d", path, resp.StatusCode, wantStatus)
		}
		if !strings.Contains(string(body), `href="/trap-link"`) || !strings.HasSuffix(string(body), "</body></html>") {
			t.Errorf("GET %s: body %q, want the page intact with the trap link injected", path, body)
		}
	}
}
