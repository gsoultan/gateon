// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Nothing capped the requests in flight to one backend, so the connections to
// it numbered whatever concurrency an attacker could create -- 18,822
// descriptors in the 2026-11-13 rapid-reset experiment -- and the flood went
// on to the backend (review D3). A request past the cap now waits the queue
// timeout for a slot and is then answered 503 with Retry-After, without being
// charged to the backend.
func TestABackendAtItsCapAnswers503(t *testing.T) {
	t.Setenv("GATEON_BACKEND_MAX_INFLIGHT", "1")
	t.Setenv("GATEON_BACKEND_QUEUE_TIMEOUT", "50ms")
	arrived, release := make(chan struct{}), make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			arrived <- struct{}{}
			<-release
		}
	}))
	defer backend.Close()
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	defer free() // before backend.Close, which waits for the held handler
	reg := config.NewServiceRegistry(filepath.Join(t.TempDir(), "services.json"))
	if err := reg.Update(context.Background(), &gateonv1.Service{
		Id: "capped", Name: "capped", WeightedTargets: []*gateonv1.Target{{Url: backend.URL}},
	}); err != nil {
		t.Fatal(err)
	}
	ph := NewProxyHandler(&gateonv1.Route{Id: "capped-route", ServiceId: "capped"}, reg)
	defer ph.Close()

	held := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		ph.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/hold", nil))
		held <- rec.Code
	}()
	<-arrived

	rec := httptest.NewRecorder()
	ph.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("second request: %d, Retry-After %q; want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}

	free()
	if code := <-held; code != http.StatusOK {
		t.Fatalf("the held request: %d", code)
	}
	rec = httptest.NewRecorder()
	ph.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("after the slot freed: %d", rec.Code)
	}
	if stats := ph.GetStats(); len(stats) != 1 || stats[0].ErrorCount != 0 {
		t.Fatalf("stats = %+v, want the refusal not charged to the backend", stats)
	}
}
