// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// BenchmarkUserMitigation measures the fingerprint block on the path a request
// takes through it most often: not blocked. ADR 0026 keys the block on the
// scoped identity (telemetry.GetReputationID), which the reputation blocker
// behind it builds anyway; "alone" is the middleware by itself, a request's
// first consumer of that identity, and "enforcement-chain" is the three
// refusals every route carries, where the identity is built once and shared.
func BenchmarkUserMitigation(b *testing.B) {
	b.Setenv("GATEON_TRACE_DIR", filepath.Join(b.TempDir(), "traces"))
	if err := telemetry.InitPathStatsStore(filepath.Join(b.TempDir(), "bench.db"), 1); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = telemetry.ClosePathStatsStore(b.Context()) })

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	for _, tc := range []struct {
		name string
		h    http.Handler
	}{
		{"alone", UserMitigation()(ok)},
		{"enforcement-chain", IPMitigation()(UserMitigation()(ReputationBlocker("bench")(ok)))},
	} {
		b.Run(tc.name, func(b *testing.B) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/orders?page=2", nil)
			req.RemoteAddr = net.JoinHostPort("203.0.113.42", "51234")
			rs := &request.RequestState{JA4Plus: "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cr0200_7e33b58890ac"}
			req = req.WithContext(request.WithState(req.Context(), rs))
			w := httptest.NewRecorder()
			tc.h.ServeHTTP(w, req) // warm the caches the lookups answer from

			b.ReportAllocs()
			for b.Loop() {
				rs.ReputationID = ""
				tc.h.ServeHTTP(w, req)
			}
		})
	}
}

// BenchmarkExemptFromEnforcement is what the loopback and allowlist exemption
// costs a request a block would refuse -- the only request that reads it.
func BenchmarkExemptFromEnforcement(b *testing.B) {
	for _, tc := range []struct{ name, allowlist, ip string }{
		{"no-allowlist", "", "203.0.113.42"},
		{"allowlist-miss", "198.51.100.0/24,192.0.2.10/32", "203.0.113.42"},
		{"allowlist-hit", "198.51.100.0/24,203.0.113.0/24", "203.0.113.42"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			mitigation.SetAllowlist(mitigation.ParseAllowlist(tc.allowlist))
			b.Cleanup(func() { mitigation.SetAllowlist(nil) })
			b.ReportAllocs()
			for b.Loop() {
				exemptFromEnforcement(tc.ip)
			}
		})
	}
}
