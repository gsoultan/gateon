// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Deleting a service is implemented twice.
//
// The REST handler calls the domain service (internal/domain/service), which
// clears ServiceId on every route that referenced it, deletes the record, then
// invalidates. This one talks to the store directly: it deletes the record and
// invalidates, and never touches the routes.
//
// So the same operation leaves two different persisted states depending on which
// transport the caller used. The dashboard uses REST and gets the tidy one; an
// API client using Connect or gRPC leaves every referencing route pointing at a
// service that no longer exists.
//
// This codebase has been here before: authorization was once enforced on the
// REST routes while Connect and gRPC served the same methods unguarded. The
// shape is the same -- one operation, two implementations, and only one of them
// maintained.

type svcStore struct {
	config.ServiceStore
	services map[string]*gateonv1.Service
}

func (f *svcStore) Delete(_ context.Context, id string) error {
	delete(f.services, id)
	return nil
}

type rtStore struct {
	config.RouteStore
	routes []*gateonv1.Route
}

func (f *rtStore) List(context.Context) []*gateonv1.Route { return f.routes }
func (f *rtStore) Update(_ context.Context, rt *gateonv1.Route) error {
	for i, r := range f.routes {
		if r.Id == rt.Id {
			f.routes[i] = rt
			return nil
		}
	}
	return nil
}

// noopInvalidator records nothing; invalidation is not what is under test.
type noopInvalidator struct{}

func (noopInvalidator) InvalidateRoute(string)                      {}
func (noopInvalidator) InvalidateRoutes(func(*gateonv1.Route) bool) {}
func (noopInvalidator) InvalidateTLS()                              {}
func (noopInvalidator) InvalidateWAF()                              {}

// TestDeleteServiceLeavesNoDanglingRouteReferences is the post-condition both
// transports have to satisfy.
//
// A route whose ServiceId names a service that no longer exists is broken either
// way -- there is no backend to reach. What differs is what an operator sees
// afterwards: a route pointing at a live-looking id that resolves to nothing,
// versus one that plainly has no service and says so.
func TestDeleteServiceLeavesNoDanglingRouteReferences(t *testing.T) {
	svcs := &svcStore{services: map[string]*gateonv1.Service{"svc-1": {Id: "svc-1"}}}
	rts := &rtStore{routes: []*gateonv1.Route{
		{Id: "route-a", ServiceId: "svc-1"},
		{Id: "route-b", ServiceId: "svc-1"},
		{Id: "route-c", ServiceId: "svc-2"}, // untouched
	}}
	s := &ApiService{Services: svcs, Routes: rts, Invalidator: noopInvalidator{}}

	if _, err := s.DeleteService(context.Background(),
		&gateonv1.DeleteServiceRequest{Id: "svc-1"}); err != nil {
		t.Fatalf("DeleteService: %v", err)
	}

	if _, still := svcs.services["svc-1"]; still {
		t.Error("the service record survived the delete")
	}

	for _, rt := range rts.routes {
		if rt.ServiceId == "svc-1" {
			t.Errorf("route %q still references the deleted service.\n"+
				"The REST path clears this and this one does not, so the same "+
				"operation leaves two different persisted states depending on the "+
				"transport the caller happened to use. The route is broken either "+
				"way; the difference is whether it points at nothing or at an id "+
				"that looks real and resolves to nothing.", rt.Id)
		}
	}

	// A route belonging to a different service must not be touched.
	for _, rt := range rts.routes {
		if rt.Id == "route-c" && rt.ServiceId != "svc-2" {
			t.Errorf("route-c belongs to svc-2 and was modified (ServiceId=%q)",
				rt.ServiceId)
		}
	}
}
