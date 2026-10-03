// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// managementInflight is the base handler's in-flight limit on the management
// plane, the second one a management request meets after the listener's own.
const managementInflight = 500

// TestTheBaseHandlerAnswersHealthWhileItsInflightSlotsAreHeld (review finding
// MGMT-N4): the base handler's management chain has its own 500-request
// in-flight limit, and /healthz took a slot like any request. With every slot
// held -- the review's two addresses sending slow bodies -- the probe was
// answered 503, and the orchestrator's liveness probe restarted the pod.
func TestTheBaseHandlerAnswersHealthWhileItsInflightSlotsAreHeld(t *testing.T) {
	entered, release := make(chan struct{}, managementInflight), make(chan struct{})
	ui := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
	})
	probes := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	deps := BaseHandlerDeps{
		ProxyHandler: probes,
		RouteStore:   &mockRouteStore{},
		GlobalReg:    &mockGlobalReg{config: &gateonv1.GlobalConfig{}},
	}
	h := CreateBaseHandler(ui, deps, nil, http.NewServeMux())
	onManagement := func(method, path string) *http.Request {
		req := httptest.NewRequest(method, path, nil)
		return req.WithContext(context.WithValue(req.Context(), middleware.EntryPointIDContextKey, "management"))
	}

	var held sync.WaitGroup
	defer held.Wait()
	defer close(release) // runs first: every held request returns, then Wait
	for range managementInflight {
		held.Go(func() { h.ServeHTTP(httptest.NewRecorder(), onManagement(http.MethodGet, "/")) })
	}
	for range managementInflight {
		<-entered
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, path := range []string{"/healthz", "/readyz"} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, onManagement(method, path))
			if rec.Code != http.StatusOK {
				t.Errorf("%s %s answered %d while all %d management in-flight slots were held; want 200",
					method, path, rec.Code, managementInflight)
			}
		}
	}
	// Anything else is still limited: the exemption is the probe, not the path.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, onManagement(http.MethodPost, "/healthz"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("POST /healthz answered %d with every slot held; want 503 -- only a bodiless GET or HEAD is a probe", rec.Code)
	}
}
