// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// This package had no tests. Deleting a service is the riskiest thing in it:
// it is the one operation that reaches across aggregates and rewrites records
// belonging to something else.

type fakeServiceStore struct {
	config.ServiceStore
	services  map[string]*gateonv1.Service
	deleteErr error
}

func (f *fakeServiceStore) Delete(_ context.Context, id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.services, id)
	return nil
}
func (f *fakeServiceStore) Update(_ context.Context, svc *gateonv1.Service) error {
	f.services[svc.Id] = svc
	return nil
}

// fakeRouteStore locks like the real registry does. Without that its own slice
// write races the reader in TestClearRouteReferencesDoesNotRaceTheRequestPath
// and the detector reports the fixture instead of the code under test.
type fakeRouteStore struct {
	config.RouteStore
	mu        sync.RWMutex
	routes    []*gateonv1.Route
	updateErr map[string]error
}

func (f *fakeRouteStore) List(context.Context) []*gateonv1.Route {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.routes
}

func (f *fakeRouteStore) Update(_ context.Context, rt *gateonv1.Route) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.updateErr[rt.Id]; err != nil {
		return err
	}
	// A new backing array rather than an in-place write: List hands out the
	// slice under a read lock that is released on return, so a reader may still
	// be walking the old one.
	next := make([]*gateonv1.Route, len(f.routes))
	copy(next, f.routes)
	for i, r := range next {
		if r.Id == rt.Id {
			next[i] = rt
			f.routes = next
			return nil
		}
	}
	return nil
}

type recordingInvalidator struct{ routes []string }

func (r *recordingInvalidator) InvalidateRoute(id string)                   { r.routes = append(r.routes, id) }
func (r *recordingInvalidator) InvalidateRoutes(func(*gateonv1.Route) bool) {}
func (r *recordingInvalidator) InvalidateTLS()                              {}
func (r *recordingInvalidator) InvalidateWAF()                              {}

func fixture(t *testing.T) (*fakeServiceStore, *fakeRouteStore, *recordingInvalidator, Service) {
	t.Helper()
	svcs := &fakeServiceStore{services: map[string]*gateonv1.Service{"svc-1": {Id: "svc-1"}}}
	rts := &fakeRouteStore{
		routes: []*gateonv1.Route{
			{Id: "route-a", ServiceId: "svc-1"},
			{Id: "route-b", ServiceId: "svc-1"},
			{Id: "route-c", ServiceId: "svc-2"},
		},
		updateErr: map[string]error{},
	}
	inv := &recordingInvalidator{}
	return svcs, rts, inv, NewService(svcs, rts, inv, nil)
}

// TestDeleteServiceDoesAllThreeThings pins the whole operation.
//
// Delete is three steps that have to happen together: clear the references,
// remove the record, invalidate the proxies that were built from it. Any one of
// them alone leaves the gateway in a state no operator asked for.
func TestDeleteServiceDoesAllThreeThings(t *testing.T) {
	svcs, rts, inv, s := fixture(t)

	if err := s.DeleteService(context.Background(), "svc-1"); err != nil {
		t.Fatalf("DeleteService: %v", err)
	}

	if _, still := svcs.services["svc-1"]; still {
		t.Error("the service record survived; the operator asked for it to be gone")
	}
	for _, rt := range rts.routes {
		if rt.Id != "route-c" && rt.ServiceId != "" {
			t.Errorf("route %q still points at the deleted service", rt.Id)
		}
	}
	if len(inv.routes) != 2 {
		t.Errorf("invalidated %v, want both affected routes; a route whose service "+
			"changed keeps serving from a proxy built against the old one until "+
			"something tells it otherwise", inv.routes)
	}
}

// TestDeleteServiceLeavesOtherServicesRoutesAlone is the blast-radius check.
func TestDeleteServiceLeavesOtherServicesRoutesAlone(t *testing.T) {
	_, rts, inv, s := fixture(t)

	if err := s.DeleteService(context.Background(), "svc-1"); err != nil {
		t.Fatalf("DeleteService: %v", err)
	}

	for _, rt := range rts.routes {
		if rt.Id == "route-c" && rt.ServiceId != "svc-2" {
			t.Errorf("route-c belongs to svc-2 and was cleared (ServiceId=%q); "+
				"deleting one service must not touch another's routes", rt.ServiceId)
		}
	}
	for _, id := range inv.routes {
		if id == "route-c" {
			t.Error("route-c was invalidated; it was not affected")
		}
	}
}

// TestDeleteServiceRefusesAnEmptyID covers the guard.
func TestDeleteServiceRefusesAnEmptyID(t *testing.T) {
	svcs, rts, _, s := fixture(t)

	if err := s.DeleteService(context.Background(), ""); err == nil {
		t.Error("an empty id was accepted; with no id to match, the reference sweep " +
			"would clear every route that happens to have no service set")
	}
	if len(svcs.services) != 1 {
		t.Error("an empty id deleted something")
	}
	for _, rt := range rts.routes {
		if rt.ServiceId == "" {
			t.Errorf("route %q was cleared by a delete with no id", rt.Id)
		}
	}
}

// TestDeleteServiceReportsAFailedDelete covers the error path.
//
// The references are cleared first, so a failed delete leaves the routes already
// detached. Returning the error is what tells the operator the state is
// half-applied rather than letting it read as success.
func TestDeleteServiceReportsAFailedDelete(t *testing.T) {
	svcs, _, inv, s := fixture(t)
	svcs.deleteErr = errors.New("store is read-only")

	if err := s.DeleteService(context.Background(), "svc-1"); err == nil {
		t.Fatal("a failing store delete was reported as success; the service is " +
			"still there and its routes are already detached")
	}
	if len(inv.routes) != 0 {
		t.Errorf("proxies were invalidated (%v) after the delete failed", inv.routes)
	}
}

// TestClearRouteReferencesSkipsAFailedUpdate pins the partial-failure choice.
//
// One route failing to save does not abort the sweep. The service is going away
// regardless, and stopping halfway would leave some routes detached and others
// pointing at a service that no longer exists -- a worse state than one route
// left behind where an operator can see it.
func TestClearRouteReferencesSkipsAFailedUpdate(t *testing.T) {
	_, rts, _, _ := fixture(t)
	rts.updateErr["route-a"] = errors.New("write failed")

	affected := ClearRouteReferences(context.Background(), rts, "svc-1")

	if len(affected) != 2 {
		t.Errorf("affected = %v, want both routes reported even though one failed "+
			"to save; the caller invalidates from this list", affected)
	}
	var cleared int
	for _, rt := range rts.routes {
		if rt.Id != "route-c" && rt.ServiceId == "" {
			cleared++
		}
	}
	if cleared != 1 {
		t.Errorf("%d routes were cleared, want 1 -- the sweep must continue past a "+
			"route it could not save", cleared)
	}
}

// TestClearRouteReferencesDoesNotRaceTheRequestPath is the regression test.
//
// RouteRegistry.List returns the registry's own slice of live pointers under a
// read lock it releases on return, and the request path reads those objects
// while it routes. Clearing ServiceId in place therefore wrote to a struct
// another goroutine was reading -- the detector flagged it against every
// concurrent read of the field, and the fix is that the sweep clones each route
// rather than editing the shared one.
//
// Run with -race; without it this passes regardless and proves nothing.
func TestClearRouteReferencesDoesNotRaceTheRequestPath(t *testing.T) {
	rts := &fakeRouteStore{
		routes:    []*gateonv1.Route{{Id: "route-a", ServiceId: "svc-1"}},
		updateErr: map[string]error{},
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // stands in for the request path reading a route it is serving
		defer wg.Done()
		for range 2000 {
			for _, rt := range rts.List(context.Background()) {
				_ = rt.ServiceId
			}
		}
	}()
	go func() { // an operator deleting the service
		defer wg.Done()
		for range 2000 {
			ClearRouteReferences(context.Background(), rts, "svc-1")
		}
	}()
	wg.Wait()
}
