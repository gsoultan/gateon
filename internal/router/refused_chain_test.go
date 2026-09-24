// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestRefusedChainDoesNotLogEveryRequest floods a route whose security
// middleware is missing. The route refuses every request until it is fixed,
// and it used to write an ERROR line for each one, so anyone who could reach
// the route could fill the disk and bury the log on a small host.
func TestRefusedChainDoesNotLogEveryRequest(t *testing.T) {
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	rt := &gateonv1.Route{Id: "r1", Name: "r1", Middlewares: []string{"missing"}}
	h := ApplyRouteMiddlewares(backend, rt, nil, &stubMiddlewareStore{}, nil, nil, nil)

	rc, ok := h.(*RefusedChain)
	if !ok {
		t.Fatalf("a route naming a missing middleware built %T, want *RefusedChain", h)
	}
	var lines atomic.Int32
	rc.logf = func(string, ...any) { lines.Add(1) }

	for i := range 100 {
		rec := httptest.NewRecorder()
		rc.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("request %d: status %d, want 503", i, rec.Code)
		}
	}
	if n := lines.Load(); n != 1 {
		t.Fatalf("100 refused requests wrote %d log lines, want 1", n)
	}
}
