// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package kind

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const customPage = "<h1>Something went wrong, and it is not you</h1>"

// TestCustomErrorPageArrivesWhole: the page replaced the backend's error body
// but kept the backend's headers -- through the proxy, its Content-Length and
// Content-Encoding. The server stopped the page at the length the backend had
// declared for its own body, and a gzip-encoded error announced the plain HTML
// page as gzip.
func TestCustomErrorPageArrivesWhole(t *testing.T) {
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// What the reverse proxy copies from an upstream error response.
		w.Header().Set("Content-Length", "9")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	})
	srv := httptest.NewServer(Errors(ErrorsConfig{
		StatusCodes: []int{404}, CustomPages: map[int]string{404: customPage},
	})(backend))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound || string(body) != customPage {
		t.Fatalf("status %d body %q, want 404 and the whole custom page", resp.StatusCode, body)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		t.Errorf("custom page sent with Content-Encoding %q", enc)
	}
}

// TestErrorsMiddlewareKeepsStreamingAndUpgrades: the writer embedded the
// ResponseWriter interface, which promotes Header, Write and WriteHeader and
// nothing else. Behind it a handler could not flush -- server-sent events
// arrived all at once at the end -- and could not hijack, so the proxy
// answered every websocket upgrade 500.
func TestErrorsMiddlewareKeepsStreamingAndUpgrades(t *testing.T) {
	var flusher, hijacker bool
	h := Errors(ErrorsConfig{CustomPages: map[int]string{502: customPage}})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, flusher = w.(http.Flusher)
			_, hijacker = w.(http.Hijacker)
		}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if !flusher || !hijacker {
		t.Fatalf("behind the errors middleware: Flusher=%v Hijacker=%v, want both", flusher, hijacker)
	}
}
