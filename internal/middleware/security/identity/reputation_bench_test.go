// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// BenchmarkReputationBlockerIdentity measures the blocker every route carries,
// on the fingerprints real clients present: a TLS client's full JA4+, a
// plaintext client's (no JA4, so the identity comes from JA4H), and a TLS
// client on IPv6.
//
// ADR 0011 bought its scoped identity for about +55ns and one allocation on this
// path and said so; ADR 0024 changes what the identity is built from, and this
// is the number that says what that costs. The identity is cleared per
// iteration so the loop measures a request's first reputation consumer, which is
// the one that builds it; the resolved client address stays cached, as it would
// be by then.
func BenchmarkReputationBlockerIdentity(b *testing.B) {
	h := ReputationBlocker("bench-identity")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, tc := range []struct{ name, ja4Plus, ip string }{
		{"tls-ipv4", "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cr0200_7e33b58890ac", "203.0.113.42"},
		{"plaintext-ipv4", "_ge11cr0200_7e33b58890ac", "203.0.113.42"},
		{"tls-ipv6", "t13d1516h2_8daaf6152771_b0da82dd1658_ge20cr02h2_7e33b58890ac", "2001:db8:1:2::42"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/orders?page=2", nil)
			req.RemoteAddr = net.JoinHostPort(tc.ip, "51234")
			rs := &request.RequestState{JA4Plus: tc.ja4Plus}
			req = req.WithContext(request.WithState(req.Context(), rs))
			w := httptest.NewRecorder()

			b.ReportAllocs()
			for b.Loop() {
				rs.ReputationID = ""
				h.ServeHTTP(w, req)
			}
		})
	}
}
