// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// BenchmarkDataPlaneRequest is one request through a data-plane entrypoint as
// production assembles it -- the entrypoint middleware, the base handler, the
// route's chain and the proxy -- to a local backend, with and without the
// management credentials ADR 0051 withholds as the request enters. The headers
// are restored before every iteration because withholding edits the request.
func BenchmarkDataPlaneRequest(b *testing.B) {
	s, _, data := buildCredGateway(b)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	b.Cleanup(backend.Close)
	if err := s.ServiceStore.Update(b.Context(), &gateonv1.Service{
		Id: "bench", WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}},
	}); err != nil {
		b.Fatal(err)
	}
	if err := s.RouteStore.Update(b.Context(), &gateonv1.Route{
		Id: "bench", ServiceId: "bench", Type: "http", Rule: "PathPrefix(`/bench`)",
	}); err != nil {
		b.Fatal(err)
	}
	for _, bc := range []struct{ name, cookie, authz string }{
		{"no-management-credential", "a=1; theme=dark; gateon_session_r1=oidc; _ga=GA1.2.3", "Bearer eyJhbGciOi.x.y"},
		{"admin-session-cookie", "a=1; gateon_session=v4.local.ADMIN; theme=dark", ""},
		{"app-paseto-bearer", "a=1", "Bearer v4.local.APP-OWN-TOKEN-NOT-THE-GATEWAYS"},
	} {
		b.Run(bc.name, func(b *testing.B) {
			req := httptest.NewRequest(http.MethodGet, "http://gateway.test/bench", nil)
			req.RemoteAddr = "192.0.2.10:40000"
			cookie, authz := []string{bc.cookie}, []string{bc.authz}
			b.ReportAllocs()
			for b.Loop() {
				cookie[0], authz[0] = bc.cookie, bc.authz
				req.Header["Cookie"] = cookie
				if bc.authz != "" {
					req.Header["Authorization"] = authz
				}
				rr := httptest.NewRecorder()
				data.ServeHTTP(rr, req)
				if rr.Code != http.StatusOK {
					b.Fatalf("status %d", rr.Code)
				}
			}
		})
	}
}
