// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Inspecting a body holds several times its length until the request has been
// proxied, so what exhausts a small host is how many large bodies are inspected
// at once. On the built gateway, 600 clients from 600 addresses each posting a
// 1 MiB form took the process to 1.73 GB on a 2 GB budget and timed out small
// requests from unrelated users: every client stayed inside the per-address and
// per-connection caps, and nothing bounded the sum. Root cause: the WAF began an
// inspection for every body it was handed, however many were already running.

// withLargeBodySlots gives the process-wide gate n slots for one test.
func withLargeBodySlots(t *testing.T, n string) {
	t.Helper()
	t.Setenv(largeBodyInspectionsEnv, n)
	largeBodies = largeBodyGate{}
	t.Cleanup(func() { largeBodies = largeBodyGate{} })
}

func TestALargeBodyWithNoInspectionSlotIsShedNotForwarded(t *testing.T) {
	withLargeBodySlots(t, "1")
	const route = "test-large-body-gate"

	reached := 0
	handler := inspectingWAF(t, route)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusNoContent)
	}))

	// The one slot is taken, as by an inspection still running.
	release, ok := largeBodies.acquire(t.Context())
	if !ok {
		t.Fatal("could not take the only slot")
	}

	large := strings.Repeat("a=b&", (largeBodyThreshold/4)+1)
	post := func(body string) *httptest.ResponseRecorder {
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/upload", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := post(large); rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Errorf("a large body with every slot taken got %d (Retry-After %q); want 503 with Retry-After",
			rec.Code, rec.Header().Get("Retry-After"))
	}
	if reached != 0 {
		t.Fatalf("the origin saw a large body while every inspection slot was taken")
	}

	// A small body never needs a slot, so a flood of large ones cannot starve it.
	if rec := post("a=b"); rec.Code != http.StatusNoContent {
		t.Errorf("a small body got %d while the large-body slots were full; want it inspected and passed", rec.Code)
	}

	// Once the slot is free the same large body is inspected and passed, and
	// its own slot is given back when the request is done.
	release()
	for i := range 2 {
		if rec := post(large); rec.Code != http.StatusNoContent {
			t.Fatalf("large body %d with a free slot got %d; want 204", i, rec.Code)
		}
	}
}
