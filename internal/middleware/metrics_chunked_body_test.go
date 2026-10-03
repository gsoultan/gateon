// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// ipBytesIn is what the bandwidth-by-IP card shows as ip's inbound bytes.
func ipBytesIn(t *testing.T, ip string) float64 {
	t.Helper()
	snap, err := telemetry.CollectMetricsSnapshot(context.Background(), 1, 0)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	for _, m := range snap.IPMetrics {
		if m.IP == ip {
			return m.BytesIn
		}
	}
	return 0
}

// TestAChunkedUploadIsCountedAtItsSize is T30: a request body with no
// Content-Length (chunked) was counted as 0 bytes plus the 256-byte header
// estimate, so a 1 MiB streamed upload added 256 bytes to the client's
// bandwidth and an abuser streaming uploads was invisible on the card.
//
// Sent over a real connection so the server, not the test, decides the body
// is chunked, through the entrypoint's Metrics and the route's as a proxied
// request passes them.
func TestAChunkedUploadIsCountedAtItsSize(t *testing.T) {
	const size = 1 << 20
	var announced int64
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		announced = r.ContentLength
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte("ok"))
	})
	h := Chain(EntryPoint("web", "web", false), Metrics("gateon-chunked"))(
		Chain(MetricsWithService("chunked-route", "svc"))(backend))
	srv := httptest.NewServer(h)
	defer srv.Close()

	route := telemetry.RequestBytesTotal.WithLabelValues("chunked-route", "in")
	entry := telemetry.RequestBytesTotal.WithLabelValues("gateon-chunked", "in")
	r0, e0, ip0 := counterValue(t, route), counterValue(t, entry), ipBytesIn(t, "127.0.0.1")

	// io.MultiReader hides the length, so the client sends it chunked.
	body := io.MultiReader(bytes.NewReader(make([]byte, size)))
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/upload", body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if announced != -1 {
		t.Fatalf("the server saw Content-Length %d; the upload was not chunked", announced)
	}

	const want = size + 256
	if got := counterValue(t, route) - r0; got != want {
		t.Errorf("route bytes in: +%v, want +%v", got, want)
	}
	if got := counterValue(t, entry) - e0; got != want {
		t.Errorf("entrypoint bytes in: +%v, want +%v", got, want)
	}
	if got := ipBytesIn(t, "127.0.0.1") - ip0; got != want {
		t.Errorf("bandwidth-by-IP bytes in: +%v, want +%v (counted once)", got, want)
	}
}
