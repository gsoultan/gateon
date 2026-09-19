// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The Connect and gRPC transports serve the same mutations as the REST
// handlers. REST goes through the domain services in internal/domain, which
// validate, assign ids, cascade and invalidate. These methods wrote to the
// stores directly and carried their own, thinner, copy of those rules.
//
// Each test below is a post-condition REST already satisfies, checked against
// this transport. The shape is the one this codebase keeps meeting: one
// operation, two implementations, only one of them maintained.

type parityMwStore struct {
	config.MiddlewareStore
	items map[string]*gateonv1.Middleware
}

func newParityMwStore(mws ...*gateonv1.Middleware) *parityMwStore {
	s := &parityMwStore{items: map[string]*gateonv1.Middleware{}}
	for _, m := range mws {
		s.items[m.Id] = m
	}
	return s
}

func (s *parityMwStore) List(context.Context) []*gateonv1.Middleware {
	out := make([]*gateonv1.Middleware, 0, len(s.items))
	for _, m := range s.items {
		out = append(out, m)
	}
	return out
}

func (s *parityMwStore) Get(_ context.Context, id string) (*gateonv1.Middleware, bool) {
	m, ok := s.items[id]
	return m, ok
}

func (s *parityMwStore) Update(_ context.Context, m *gateonv1.Middleware) error {
	s.items[m.Id] = m
	return nil
}

func (s *parityMwStore) Delete(_ context.Context, id string) error {
	delete(s.items, id)
	return nil
}

// parityRouteStore fails Update for the routes named in failFor.
type parityRouteStore struct {
	config.RouteStore
	routes  []*gateonv1.Route
	failFor map[string]bool
}

func newParityRouteStore(routes ...*gateonv1.Route) *parityRouteStore {
	return &parityRouteStore{routes: routes, failFor: map[string]bool{}}
}

func (s *parityRouteStore) List(context.Context) []*gateonv1.Route { return s.routes }

func (s *parityRouteStore) Get(_ context.Context, id string) (*gateonv1.Route, bool) {
	for _, r := range s.routes {
		if r.Id == id {
			return r, true
		}
	}
	return nil, false
}

func (s *parityRouteStore) Update(_ context.Context, rt *gateonv1.Route) error {
	if s.failFor[rt.Id] {
		return errors.New("store unavailable")
	}
	for i, r := range s.routes {
		if r.Id == rt.Id {
			s.routes[i] = rt
			return nil
		}
	}
	s.routes = append(s.routes, rt)
	return nil
}

func (s *parityRouteStore) Delete(_ context.Context, id string) error {
	s.routes = slices.DeleteFunc(s.routes, func(r *gateonv1.Route) bool { return r.Id == id })
	return nil
}

type parityEPStore struct {
	config.EntryPointStore
	items map[string]*gateonv1.EntryPoint
}

func (s *parityEPStore) Update(_ context.Context, ep *gateonv1.EntryPoint) error {
	s.items[ep.Id] = ep
	return nil
}

type paritySvcStore struct {
	config.ServiceStore
	items map[string]*gateonv1.Service
}

func (s *paritySvcStore) Update(_ context.Context, svc *gateonv1.Service) error {
	s.items[svc.Id] = svc
	return nil
}

func (s *paritySvcStore) Delete(_ context.Context, id string) error {
	delete(s.items, id)
	return nil
}

// parityInvalidator records which route ids were invalidated. InvalidateRoutes
// applies the predicate to the store's current routes, which is what every
// real implementation does (ProxyCache.InvalidateRoutes,
// serverProxyInvalidator.InvalidateRoutes): a predicate that matches nothing
// that is currently stored invalidates nothing.
type parityInvalidator struct {
	routes *parityRouteStore
	ids    []string
}

func (p *parityInvalidator) InvalidateRoute(id string) { p.ids = append(p.ids, id) }
func (p *parityInvalidator) InvalidateRoutes(pred func(*gateonv1.Route) bool) {
	for _, rt := range p.routes.routes {
		if pred(rt) {
			p.ids = append(p.ids, rt.Id)
		}
	}
}
func (p *parityInvalidator) InvalidateTLS() {}
func (p *parityInvalidator) InvalidateWAF() {}

type rejectingValidator struct{ err error }

func (v rejectingValidator) Validate(*gateonv1.Middleware) error { return v.err }

// TestDeleteMiddlewareOverConnectRefusesWhileARouteStillReferencesIt is the
// guard the domain service has and this transport did not.
//
// The router resolves a route's middleware ids with a plain store lookup and
// skips any that miss, silently. Deleting the record while a route still names
// it therefore removes that middleware from the route without an error, a log
// line or a failed RPC -- and when it was the WAF or an auth middleware, the
// route is now served unprotected while the operator was told it succeeded.
func TestDeleteMiddlewareOverConnectRefusesWhileARouteStillReferencesIt(t *testing.T) {
	mws := newParityMwStore(&gateonv1.Middleware{Id: "waf-1", Type: "waf"})
	rts := newParityRouteStore(
		&gateonv1.Route{Id: "route-ok", Middlewares: []string{"waf-1"}},
		&gateonv1.Route{Id: "route-bad", Middlewares: []string{"waf-1"}},
	)
	rts.failFor["route-bad"] = true
	s := &ApiService{Middlewares: mws, Routes: rts, Invalidator: &parityInvalidator{routes: rts}}

	res, err := s.DeleteMiddleware(context.Background(), &gateonv1.DeleteMiddlewareRequest{Id: "waf-1"})
	if err == nil || res.GetSuccess() {
		t.Fatalf("DeleteMiddleware reported success (err=%v) while route-bad still references "+
			"waf-1; the router skips a middleware id that no longer resolves, so that route "+
			"is now served without its WAF", err)
	}
	if _, ok := mws.Get(context.Background(), "waf-1"); !ok {
		t.Error("the middleware was deleted while a route still referenced it")
	}
}

// TestDeleteMiddlewareOverConnectUnlinksEveryRoute is the post-condition both
// transports have to satisfy: after a successful delete no route names the id.
func TestDeleteMiddlewareOverConnectUnlinksEveryRoute(t *testing.T) {
	mws := newParityMwStore(&gateonv1.Middleware{Id: "mw-1", Type: "ratelimit"})
	rts := newParityRouteStore(
		&gateonv1.Route{Id: "route-a", Middlewares: []string{"mw-1", "other"}},
		&gateonv1.Route{Id: "route-b", Middlewares: []string{"mw-1"}},
		&gateonv1.Route{Id: "route-c", Middlewares: []string{"other"}},
	)
	inv := &parityInvalidator{routes: rts}
	s := &ApiService{Middlewares: mws, Routes: rts, Invalidator: inv}

	res, err := s.DeleteMiddleware(context.Background(), &gateonv1.DeleteMiddlewareRequest{Id: "mw-1"})
	if err != nil || !res.GetSuccess() {
		t.Fatalf("DeleteMiddleware: success=%v err=%v", res.GetSuccess(), err)
	}
	if _, ok := mws.Get(context.Background(), "mw-1"); ok {
		t.Error("the middleware was not deleted")
	}
	for _, rt := range rts.routes {
		if slices.Contains(rt.Middlewares, "mw-1") {
			t.Errorf("route %q still references the deleted middleware; the router will "+
				"skip the id and serve the route without it", rt.Id)
		}
	}
	if got := rts.routes[2].Middlewares; len(got) != 1 || got[0] != "other" {
		t.Errorf("route-c did not use mw-1 and was modified: %v", got)
	}
	for _, want := range []string{"route-a", "route-b"} {
		if !slices.Contains(inv.ids, want) {
			t.Errorf("invalidated %v, want it to include %s: its cached chain still runs the deleted middleware", inv.ids, want)
		}
	}
}

// TestUpdateMiddlewareOverConnectRejectsAConfigTheFactoryCannotBuild is the
// validation REST performs before persisting anything.
//
// The router builds a route's chain from the stored config and skips a
// middleware whose Create fails. So a config the factory cannot build does not
// fail at save time here, and does not fail at request time either: the route
// simply runs without it.
func TestUpdateMiddlewareOverConnectRejectsAConfigTheFactoryCannotBuild(t *testing.T) {
	mws := newParityMwStore()
	rts := newParityRouteStore()
	s := &ApiService{
		Middlewares:         mws,
		Routes:              rts,
		Invalidator:         &parityInvalidator{routes: rts},
		MiddlewareValidator: rejectingValidator{err: errors.New("unknown middleware type: nope")},
	}

	res, err := s.UpdateMiddleware(context.Background(), &gateonv1.UpdateMiddlewareRequest{
		Middleware: &gateonv1.Middleware{Id: "m-1", Type: "nope"},
	})
	if err == nil || res.GetSuccess() {
		t.Fatalf("UpdateMiddleware accepted a config the factory cannot build (err=%v)", err)
	}
	if _, ok := mws.Get(context.Background(), "m-1"); ok {
		t.Error("the unbuildable middleware was persisted; the router skips one that fails " +
			"to build, so any route given it runs without it")
	}
}

// TestUpdateMiddlewareOverConnectAssignsAnID: a record stored under "" cannot be
// deleted, because both transports refuse an empty id.
func TestUpdateMiddlewareOverConnectAssignsAnID(t *testing.T) {
	mws := newParityMwStore()
	rts := newParityRouteStore()
	s := &ApiService{Middlewares: mws, Routes: rts, Invalidator: &parityInvalidator{routes: rts}}

	mw := &gateonv1.Middleware{Type: "request_id"}
	if _, err := s.UpdateMiddleware(context.Background(), &gateonv1.UpdateMiddlewareRequest{Middleware: mw}); err != nil {
		t.Fatalf("UpdateMiddleware: %v", err)
	}
	if mw.Id == "" {
		t.Fatal("middleware saved without an id")
	}
	if _, ok := mws.items[""]; ok {
		t.Error("middleware stored under the empty id, which neither transport can delete")
	}
}

// TestUpdateRouteOverConnectRejectsARouteWithoutAService: REST refuses a route
// with no service_id (and, unless it is L4, no rule). Stored anyway, the route
// matches traffic and has no backend to send it to.
func TestUpdateRouteOverConnectRejectsARouteWithoutAService(t *testing.T) {
	rts := newParityRouteStore()
	s := &ApiService{Routes: rts, Invalidator: &parityInvalidator{routes: rts}}

	res, err := s.UpdateRoute(context.Background(), &gateonv1.UpdateRouteRequest{
		Route: &gateonv1.Route{Id: "r-1", Rule: "Host(`api.example.com`)"},
	})
	if err == nil || res.GetSuccess() {
		t.Fatalf("UpdateRoute accepted a route with no service (err=%v)", err)
	}
	if _, ok := rts.Get(context.Background(), "r-1"); ok {
		t.Error("the route with no service was persisted")
	}
}

func TestUpdateRouteOverConnectAssignsAnID(t *testing.T) {
	rts := newParityRouteStore()
	s := &ApiService{Routes: rts, Invalidator: &parityInvalidator{routes: rts}}

	rt := &gateonv1.Route{ServiceId: "svc-1", Rule: "Host(`api.example.com`)"}
	if _, err := s.UpdateRoute(context.Background(), &gateonv1.UpdateRouteRequest{Route: rt}); err != nil {
		t.Fatalf("UpdateRoute: %v", err)
	}
	if rt.Id == "" {
		t.Fatal("route saved without an id")
	}
	if _, ok := rts.Get(context.Background(), ""); ok {
		t.Error("route stored under the empty id, which neither transport can delete")
	}
}

// TestUpdateEntryPointOverConnectRejectsAnEmptyAddress: REST refuses it.
//
// Stored, every runner in internal/server/entrypoint returns on `addr == ""`
// without a log line, so the entrypoint is listed in the dashboard, can be bound
// to a route, and never listens on anything. The save is the only place that can
// say so; by the time it silently does nothing there is nothing left to report.
func TestUpdateEntryPointOverConnectRejectsAnEmptyAddress(t *testing.T) {
	eps := &parityEPStore{items: map[string]*gateonv1.EntryPoint{}}
	rts := newParityRouteStore()
	s := &ApiService{EntryPoints: eps, Invalidator: &parityInvalidator{routes: rts}}

	res, err := s.UpdateEntryPoint(context.Background(), &gateonv1.UpdateEntryPointRequest{
		EntryPoint: &gateonv1.EntryPoint{Id: "ep-1", Name: "web"},
	})
	if err == nil || res.GetSuccess() {
		t.Fatalf("UpdateEntryPoint accepted an entrypoint with no address (err=%v)", err)
	}
	if _, ok := eps.items["ep-1"]; ok {
		t.Error("the entrypoint with no address was persisted")
	}
}

// TestDeleteServiceOverConnectInvalidatesTheRoutesThatUsedIt.
//
// This method clears ServiceId from every route naming the service, then
// invalidates with the predicate `r.ServiceId == id`. Every real InvalidateRoutes
// evaluates that against the store's current routes -- which no longer carry the
// id -- so nothing was invalidated, and the cached proxy for each of those routes
// kept forwarding to the deleted service's backends.
func TestDeleteServiceOverConnectInvalidatesTheRoutesThatUsedIt(t *testing.T) {
	svcs := &paritySvcStore{items: map[string]*gateonv1.Service{"svc-1": {Id: "svc-1"}}}
	rts := newParityRouteStore(
		&gateonv1.Route{Id: "route-a", ServiceId: "svc-1"},
		&gateonv1.Route{Id: "route-b", ServiceId: "svc-1"},
		&gateonv1.Route{Id: "route-c", ServiceId: "svc-2"},
	)
	inv := &parityInvalidator{routes: rts}
	s := &ApiService{Services: svcs, Routes: rts, Invalidator: inv}

	if _, err := s.DeleteService(context.Background(), &gateonv1.DeleteServiceRequest{Id: "svc-1"}); err != nil {
		t.Fatalf("DeleteService: %v", err)
	}
	for _, want := range []string{"route-a", "route-b"} {
		if !slices.Contains(inv.ids, want) {
			t.Errorf("invalidated %v, want it to include %s: its cached proxy still "+
				"forwards to the deleted service's backends", inv.ids, want)
		}
	}
	if slices.Contains(inv.ids, "route-c") {
		t.Errorf("route-c belongs to svc-2 and was invalidated")
	}
}

func TestUpdateServiceOverConnectAssignsAnID(t *testing.T) {
	svcs := &paritySvcStore{items: map[string]*gateonv1.Service{}}
	rts := newParityRouteStore()
	s := &ApiService{Services: svcs, Routes: rts, Invalidator: &parityInvalidator{routes: rts}}

	svc := &gateonv1.Service{Name: "backend"}
	if _, err := s.UpdateService(context.Background(), &gateonv1.UpdateServiceRequest{Service: svc}); err != nil {
		t.Fatalf("UpdateService: %v", err)
	}
	if svc.Id == "" {
		t.Fatal("service saved without an id")
	}
	if _, ok := svcs.items[""]; ok {
		t.Error("service stored under the empty id, which neither transport can delete")
	}
}
