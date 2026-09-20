// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/transform"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func buildTransformMW(t *testing.T, cfg map[string]string, origin http.Handler) http.Handler {
	t.Helper()
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	mw, err := f.Create(&gateonv1.Middleware{Type: "transform", Config: cfg}, "route-a")
	if err != nil {
		t.Fatalf("create transform middleware: %v", err)
	}
	return mw(origin)
}

// A real server is used on purpose: httptest.ResponseRecorder does not enforce
// Content-Length, net/http does, and the defect is what the client receives.
func TestBodyTransformResponseKeepsContentLengthConsistent(t *testing.T) {
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "11")
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello world"))
	})
	srv := httptest.NewServer(buildTransformMW(t, map[string]string{
		"response_search": "world", "response_replace": "gateon-gateway",
	}, origin))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	body, err := io.ReadAll(resp.Body)
	const want = "hello gateon-gateway"
	if err != nil || string(body) != want {
		t.Fatalf("client received %q (err %v), want %q: Content-Length was sent before the body was rewritten", body, err, want)
	}
	if resp.ContentLength != int64(len(want)) {
		t.Fatalf("Content-Length %d, want %d", resp.ContentLength, len(want))
	}
	if resp.Header.Get("ETag") != "" {
		t.Fatalf("ETag %q survived a body rewrite", resp.Header.Get("ETag"))
	}
}

func TestBodyTransformPassesOversizedResponseThroughUntouched(t *testing.T) {
	big := append(bytes.Repeat([]byte("a"), transform.MaxBodyBytes+1), []byte("world")...)
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(big)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(big)
	})
	srv := httptest.NewServer(buildTransformMW(t, map[string]string{
		"response_search": "world", "response_replace": "gateon",
	}, origin))
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	body, err := io.ReadAll(resp.Body)
	if err != nil || !bytes.Equal(body, big) {
		t.Fatalf("client received %d bytes ending %q (err %v); a response over the buffer bound must pass through intact", len(body), tail(body), err)
	}
}

func TestBodyTransformPassesOversizedRequestThroughUntouched(t *testing.T) {
	big := strings.Repeat("a", transform.MaxBodyBytes+1) + "world"
	var seen []byte
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	})
	h := buildTransformMW(t, map[string]string{"request_search": "world", "request_replace": "gateon"}, origin)

	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(big))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if string(seen) != big {
		t.Fatalf("origin received %d bytes ending %q; a request over the buffer bound must pass through intact", len(seen), tail(seen))
	}
}

func tail(b []byte) string {
	if len(b) > 8 {
		b = b[len(b)-8:]
	}
	return string(b)
}
