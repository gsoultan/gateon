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

func twoTargetService(t *testing.T, healthPath string) (config.ServiceStore, string, string) {
	t.Helper()
	serve := func(name string) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(name))
		}))
		t.Cleanup(s.Close)
		return s
	}
	a, b := serve("a"), serve("b")
	reg := config.NewServiceRegistry(filepath.Join(t.TempDir(), "services.json"))
	if err := reg.Update(context.Background(), &gateonv1.Service{
		Id: "svc", Name: "svc", HealthCheckPath: healthPath,
		WeightedTargets: []*gateonv1.Target{{Url: a.URL}, {Url: b.URL}},
	}); err != nil {
		t.Fatal(err)
	}
	return reg, a.URL, b.URL
}

// TestRebuiltHandlerKeepsItsDownTargets: a handler built to replace another
// started every target alive and learned otherwise at its first check, fifteen
// seconds later -- so every configuration change sent traffic back to a
// backend already known to be down.
func TestRebuiltHandlerKeepsItsDownTargets(t *testing.T) {
	reg, _, down := twoTargetService(t, "/health")
	rt := &gateonv1.Route{Id: "r", ServiceId: "svc"}
	before := NewProxyHandler(rt, reg)
	defer before.Close()
	// What the health loop does when a check fails.
	before.healthThresholds.Record(down, false)
	before.lb.SetAlive(down, false)

	after := NewProxyHandler(rt, reg)
	defer after.Close()
	after.InheritHealth(before.HealthSnapshot())

	for range 10 {
		rec := httptest.NewRecorder()
		after.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
		if rec.Body.String() != "a" {
			t.Fatalf("the rebuilt handler sent a request to %q, a target its predecessor had found down", rec.Body)
		}
	}
}

// TestInheritedHealthNeedsAHealthCheck: a target marked down by a handler with
// nothing to check it would stay down for good, so a handler without a health
// check inherits nothing.
func TestInheritedHealthNeedsAHealthCheck(t *testing.T) {
	reg, _, down := twoTargetService(t, "")
	ph := NewProxyHandler(&gateonv1.Route{Id: "r", ServiceId: "svc"}, reg)
	defer ph.Close()
	ph.InheritHealth(map[string]bool{down: false})
	for _, s := range ph.GetStats() {
		if !s.Alive {
			t.Fatalf("target %s marked down on a handler that never checks it", s.URL)
		}
	}
	if snap := ph.HealthSnapshot(); snap != nil {
		t.Fatalf("snapshot %v from a handler that checks nothing", snap)
	}
}
