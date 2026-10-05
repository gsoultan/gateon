// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// BenchmarkIPMitigationIPv6 is BenchmarkIPMitigation's no-feed case for an
// IPv6 client, which since ADR 0058 is keyed by its /64.
func BenchmarkIPMitigationIPv6(b *testing.B) {
	b.Setenv("GATEON_TRACE_DIR", filepath.Join(b.TempDir(), "traces"))
	if err := telemetry.InitPathStatsStore(filepath.Join(b.TempDir(), "bench.db"), 1); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = telemetry.ClosePathStatsStore(b.Context()) })
	h := IPMitigation()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/orders?page=2", nil)
	req.RemoteAddr = net.JoinHostPort("2001:db8:1:2:3:4:5:6", "51234")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req) // warm the mitigation cache
	b.ReportAllocs()
	for b.Loop() {
		h.ServeHTTP(w, req)
	}
}
