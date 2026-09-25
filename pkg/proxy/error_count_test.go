// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestTransportErrorCountsOnce: the reverse proxy's error handler counted a
// failed dial and answered 502, and recordMetrics then counted the 502 --
// every transport error was two errors against one request, so the dashboard
// showed a target failing at twice its real rate.
func TestTransportErrorCountsOnce(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close() // its port now refuses connections

	reg := config.NewServiceRegistry(filepath.Join(t.TempDir(), "services.json"))
	if err := reg.Update(context.Background(), &gateonv1.Service{
		Id: "gone", Name: "gone", WeightedTargets: []*gateonv1.Target{{Url: gone.URL}},
	}); err != nil {
		t.Fatal(err)
	}
	ph := NewProxyHandler(&gateonv1.Route{Id: "gone-route", ServiceId: "gone"}, reg)
	defer ph.Close()

	rec := httptest.NewRecorder()
	ph.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 from a refused dial", rec.Code)
	}
	stats := ph.GetStats()
	if len(stats) != 1 || stats[0].RequestCount != 1 || stats[0].ErrorCount != 1 {
		t.Fatalf("stats = %+v, want one request and one error", stats)
	}
}
