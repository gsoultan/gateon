// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// flakyBackend answers 503 for its first failures calls, then echoes the body.
func flakyBackend(failures int32, calls *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if n <= failures {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("backend down"))
			return
		}
		w.Header().Set("X-Attempt", "ok")
		_, _ = w.Write([]byte("ok:" + string(body)))
	})
}

func retrying(attempts int, next http.Handler) http.Handler {
	return Retry(RetryConfig{Attempts: attempts, InitialInterval: time.Millisecond})(next)
}

// TestRetryResendsAFailedIdempotentRequest is the behaviour the middleware was
// named for and never had: it forwarded once and stopped.
func TestRetryResendsAFailedIdempotentRequest(t *testing.T) {
	var calls atomic.Int32
	rec := httptest.NewRecorder()
	retrying(3, flakyBackend(2, &calls)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok:" || rec.Header().Get("X-Attempt") != "ok" {
		t.Fatalf("after two failures and a success: status %d body %q; want 200 %q", rec.Code, rec.Body, "ok:")
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("backend called %d times, want 3", got)
	}
}

func TestRetryStopsAtItsAttempts(t *testing.T) {
	var calls atomic.Int32
	rec := httptest.NewRecorder()
	retrying(3, flakyBackend(99, &calls)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if calls.Load() != 3 || rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "backend down" {
		t.Fatalf("calls %d, status %d, body %q; want 3 calls and the last failure passed on", calls.Load(), rec.Code, rec.Body)
	}
}

// TestRetryNeverResendsAPost keeps a payment or an order from being placed
// twice because the first attempt's response was lost.
func TestRetryNeverResendsAPost(t *testing.T) {
	var calls atomic.Int32
	rec := httptest.NewRecorder()
	retrying(3, flakyBackend(1, &calls)).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("x")))
	if calls.Load() != 1 || rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST: %d calls, status %d; want 1 call and the failure passed on", calls.Load(), rec.Code)
	}
}

func TestRetryReplaysTheBody(t *testing.T) {
	var calls atomic.Int32
	rec := httptest.NewRecorder()
	retrying(2, flakyBackend(1, &calls)).ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/", strings.NewReader("payload")))
	if rec.Body.String() != "ok:payload" {
		t.Fatalf("the retried PUT reached the backend as %q, want the original body", rec.Body)
	}
}

// TestRetryDoesNotHoldASuccessfulStream checks the first byte of a successful
// response reaches the client before the handler finishes.
func TestRetryDoesNotHoldASuccessfulStream(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(retrying(3, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("first"))
		w.(http.Flusher).Flush()
		<-release
	})))
	defer srv.Close()
	defer close(release)

	// Bounded, so a regression fails here instead of hanging the package: the
	// handler does not finish until the test does.
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("no response headers within 5s: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(resp.Body, buf); err != nil || string(buf) != "first" {
		t.Fatalf("read %q, %v; the first chunk of a streaming response was held back", buf, err)
	}
}
