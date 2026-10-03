// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/security/reputation"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// BenchmarkIPMitigation measures the IP decision every entrypoint and route
// makes, on the path nearly every request takes: not blocked. ADR 0044 added
// the threat-feed listing to it; "no-feed" is the stock install (nothing
// published, or nothing loaded) and "feed-4k" a store holding 4096 prefixes
// that do not list the client.
func BenchmarkIPMitigation(b *testing.B) {
	b.Setenv("GATEON_TRACE_DIR", filepath.Join(b.TempDir(), "traces"))
	if err := telemetry.InitPathStatsStore(filepath.Join(b.TempDir(), "bench.db"), 1); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = telemetry.ClosePathStatsStore(b.Context()) })
	b.Cleanup(func() { reputation.Publish(nil) })

	loaded := reputation.NewIPReputationStore(&gateonv1.IPReputationConfig{Enabled: true})
	for i := range 4096 {
		loaded.SetIPScore(fmt.Sprintf("10.%d.%d.1", i/256, i%256), 100)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := IPMitigation()(ok)
	for _, tc := range []struct {
		name  string
		store *reputation.IPReputationStore
	}{{"no-feed", nil}, {"feed-4k", loaded}} {
		b.Run(tc.name, func(b *testing.B) {
			reputation.Publish(tc.store)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/orders?page=2", nil)
			req.RemoteAddr = net.JoinHostPort("203.0.113.42", "51234")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req) // warm the mitigation cache
			b.ReportAllocs()
			for b.Loop() {
				h.ServeHTTP(w, req)
			}
		})
	}
}
