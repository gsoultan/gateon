// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestRetryFailsOverFromADeadBackend puts one dead and one live backend behind
// round robin with the retry middleware on the route, and sends requests
// through the real chain and proxy. Every request must succeed: the attempt
// that lands on the dead backend is answered 502 by the proxy and retried on
// the next target. The middleware used to forward once, so every other
// request failed while the route showed retries configured.
func TestRetryFailsOverFromADeadBackend(t *testing.T) {
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("live"))
	}))
	defer live.Close()
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	services := config.NewServiceRegistry(filepath.Join(t.TempDir(), "services.json"))
	if err := services.Update(context.Background(), &gateonv1.Service{
		Id: "svc", Name: "svc", LoadBalancerPolicy: "round_robin",
		WeightedTargets: []*gateonv1.Target{{Url: deadURL, Weight: 1}, {Url: live.URL, Weight: 1}},
	}); err != nil {
		t.Fatal(err)
	}
	rt := &gateonv1.Route{Id: "r-retry", ServiceId: "svc", Rule: "PathPrefix(`/`)", Type: "http", Middlewares: []string{"retry"}}
	mw := fakeMWStore{m: map[string]*gateonv1.Middleware{
		"retry": {Id: "retry", Type: "retry", Config: map[string]string{"attempts": "2"}},
	}}
	ph := proxy.NewProxyHandler(rt, services)
	t.Cleanup(ph.Close)
	srv := httptest.NewServer(middleware.EntryPoint("web", "web", false)(
		ApplyRouteMiddlewares(ph, rt, nil, mw, fakeGlobalStore{cfg: &gateonv1.GlobalConfig{}}, nil, nil)))
	t.Cleanup(srv.Close)

	failed := 0
	for range 10 {
		resp, err := http.Get(srv.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			failed++
		}
	}
	if failed != 0 {
		t.Fatalf("%d of 10 requests failed with one live backend and retries configured", failed)
	}
}
