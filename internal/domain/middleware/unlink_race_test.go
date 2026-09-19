// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// lockedRouteStore locks like the real registry does, and like the registry
// hands out a new backing array on Update rather than writing into the one a
// reader may still be walking. Without that the fixture's own slice write races
// the reader below and the detector reports the fixture instead of the code
// under test.
type lockedRouteStore struct {
	config.RouteStore
	mu     sync.RWMutex
	routes []*gateonv1.Route
}

func (s *lockedRouteStore) List(context.Context) []*gateonv1.Route {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.routes
}

func (s *lockedRouteStore) Update(_ context.Context, rt *gateonv1.Route) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make([]*gateonv1.Route, len(s.routes))
	copy(next, s.routes)
	for i, r := range next {
		if r.Id == rt.Id {
			next[i] = rt
		}
	}
	s.routes = next
	return nil
}

// TestDeleteMiddlewareDoesNotRaceTheRequestPath is the same defect
// service.ClearRouteReferences was fixed for, one package over.
//
// RouteRegistry.List returns the registry's own slice of live pointers, and the
// router reads rt.Middlewares off those same objects every time it builds a
// route's chain. DeleteMiddleware wrote the field in place on the shared route
// before persisting it, so an operator deleting a middleware raced every request
// being routed at the time. The fix is that the sweep clones each route rather
// than editing the one the request path is reading.
//
// Run with -race; without it this passes regardless and proves nothing.
func TestDeleteMiddlewareDoesNotRaceTheRequestPath(t *testing.T) {
	rts := &lockedRouteStore{routes: []*gateonv1.Route{
		{Id: "route-a", Middlewares: []string{"mw-1", "other"}},
	}}
	mwStore := newMwStore(&gateonv1.Middleware{Id: "mw-1", Type: "ratelimit"})
	svc := NewService(mwStore, rts, &fakeInvalidator{}, nil, &fakeWAFInvalidator{}, logger.Default())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // stands in for the router building the chain of a route it is serving
		defer wg.Done()
		for range 2000 {
			for _, rt := range rts.List(context.Background()) {
				for _, mid := range rt.Middlewares {
					_ = mid
				}
			}
		}
	}()
	go func() { // an operator deleting the middleware
		defer wg.Done()
		for range 2000 {
			_ = svc.DeleteMiddleware(context.Background(), "mw-1")
		}
	}()
	wg.Wait()

	if got := rts.List(context.Background())[0].Middlewares; len(got) != 1 || got[0] != "other" {
		t.Errorf("route middlewares = %v, want just [other]", got)
	}
}
