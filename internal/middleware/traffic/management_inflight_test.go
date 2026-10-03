// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestManagementInflightServesOnlyAProbeWithoutASlot: with the one slot held,
// a bodiless GET or HEAD of /healthz or /readyz is served, and everything else
// -- another path, another method, a probe path that declares a body -- is
// refused as MaxConnections refuses it (review finding MGMT-N4).
func TestManagementInflightServesOnlyAProbeWithoutASlot(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	h := ManagementInflight(1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			entered <- struct{}{}
			<-release
		}
	}))
	var held sync.WaitGroup
	defer held.Wait()
	defer close(release)
	held.Go(func() { h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/hold", nil)) })
	<-entered

	cases := []struct {
		name string
		req  *http.Request
		want int
	}{
		{"GET /healthz", httptest.NewRequest(http.MethodGet, "/healthz", nil), http.StatusOK},
		{"HEAD /readyz", httptest.NewRequest(http.MethodHead, "/readyz", nil), http.StatusOK},
		{"GET /v1/routes", httptest.NewRequest(http.MethodGet, "/v1/routes", nil), http.StatusServiceUnavailable},
		{"POST /healthz", httptest.NewRequest(http.MethodPost, "/healthz", nil), http.StatusServiceUnavailable},
		{"GET /healthz with a body", httptest.NewRequest(http.MethodGet, "/healthz", strings.NewReader("hold")),
			http.StatusServiceUnavailable},
		{"GET /healthz/x", httptest.NewRequest(http.MethodGet, "/healthz/x", nil), http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, tc.req)
		if rec.Code != tc.want {
			t.Errorf("%s with the only slot held: %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
}
