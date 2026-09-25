// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

// A response to a request without Origin carries no CORS headers, but the
// answer to one with Origin would, so it says it varies by Origin: a shared
// cache that stored it would otherwise hand it to a cross-origin caller.
func TestDefaultCORSVariesByOriginWithoutOne(t *testing.T) {
	h := DefaultCORS()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Vary", "Accept-Encoding")
		_, _ = w.Write([]byte("ok"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !slices.Contains(rec.Header().Values("Vary"), "Origin") {
		t.Fatalf("Vary is %q; it must include Origin", rec.Header().Values("Vary"))
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("a request without Origin got Access-Control-Allow-Origin %q", got)
	}
}

// A preflight that nothing downstream answers at all -- the handler returns
// without writing -- still gets the default policy's answer, not the empty
// 200 the server would write below this middleware.
func TestDefaultCORSAnswersAPreflightNothingWroteFor(t *testing.T) {
	h := DefaultCORS()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", evilOrigin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPut)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != evilOrigin {
		t.Fatalf("got %d with Access-Control-Allow-Origin %q", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

// Flushing is what puts headers on the wire, so a flush before any write
// commits the answer -- and an answered preflight's body is still discarded.
func TestDefaultCORSAnswersAPreflightThatFlushesFirst(t *testing.T) {
	h := DefaultCORS()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte("405 method not allowed"))
	}))
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", evilOrigin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPut)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 || rec.Header().Get("Content-Type") != "" {
		t.Fatalf("got %d, Content-Type %q, body %q; want the default policy's empty 204",
			rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
}
