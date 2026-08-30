// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// fakeMwStore is an in-memory MiddlewareStore.
type fakeMwStore struct {
	items     map[string]*gateonv1.Middleware
	getMisses bool
	deleteErr error
}

func newMwStore(mws ...*gateonv1.Middleware) *fakeMwStore {
	s := &fakeMwStore{items: map[string]*gateonv1.Middleware{}}
	for _, m := range mws {
		s.items[m.Id] = m
	}
	return s
}

func (s *fakeMwStore) List(context.Context) []*gateonv1.Middleware { return nil }
func (s *fakeMwStore) ListPaginated(context.Context, int32, int32, string) ([]*gateonv1.Middleware, int32) {
	return nil, 0
}
func (s *fakeMwStore) All(context.Context) map[string]*gateonv1.Middleware { return s.items }
func (s *fakeMwStore) Get(_ context.Context, id string) (*gateonv1.Middleware, bool) {
	if s.getMisses {
		return nil, false
	}
	m, ok := s.items[id]
	return m, ok
}
func (s *fakeMwStore) Update(_ context.Context, m *gateonv1.Middleware) error {
	s.items[m.Id] = m
	return nil
}
func (s *fakeMwStore) Delete(_ context.Context, id string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	delete(s.items, id)
	return nil
}

// fakeRouteStore fails Update for the routes named in failFor.
type fakeRouteStore struct {
	routes  []*gateonv1.Route
	failFor map[string]bool
}

func (s *fakeRouteStore) List(context.Context) []*gateonv1.Route          { return s.routes }
func (s *fakeRouteStore) ListWildcards(context.Context) []*gateonv1.Route { return nil }
func (s *fakeRouteStore) ListPaginated(context.Context, int32, int32, string, *config.RouteFilter) ([]*gateonv1.Route, int32) {
	return nil, 0
}
func (s *fakeRouteStore) All(context.Context) map[string]*gateonv1.Route { return nil }
func (s *fakeRouteStore) Get(_ context.Context, id string) (*gateonv1.Route, bool) {
	for _, r := range s.routes {
		if r.Id == id {
			return r, true
		}
	}
	return nil, false
}
func (s *fakeRouteStore) GetByHost(string) []*gateonv1.Route { return nil }
func (s *fakeRouteStore) GetTrieByHost(string) (*config.PathTrie, []*gateonv1.Route) {
	return nil, nil
}
func (s *fakeRouteStore) GetWildcardTrie() (*config.PathTrie, []*gateonv1.Route) { return nil, nil }
func (s *fakeRouteStore) Update(_ context.Context, rt *gateonv1.Route) error {
	if s.failFor[rt.Id] {
		return errors.New("store unavailable")
	}
	for i, r := range s.routes {
		if r.Id == rt.Id {
			s.routes[i] = rt
		}
	}
	return nil
}
func (s *fakeRouteStore) Delete(context.Context, string) error { return nil }

type fakeInvalidator struct{ routes []string }

func (f *fakeInvalidator) InvalidateRoute(id string)                   { f.routes = append(f.routes, id) }
func (f *fakeInvalidator) InvalidateRoutes(func(*gateonv1.Route) bool) {}
func (f *fakeInvalidator) InvalidateTLS()                              {}
func (f *fakeInvalidator) InvalidateWAF()                              {}

type fakeWAFInvalidator struct{ calls int }

func (f *fakeWAFInvalidator) Invalidate() { f.calls++ }

func newSvc(mwStore *fakeMwStore, rtStore *fakeRouteStore, inv *fakeInvalidator, waf *fakeWAFInvalidator) Service {
	return NewService(mwStore, rtStore, inv, nil, waf, logger.Default())
}

// TestDeleteRefusesWhenARouteCannotBeUnlinked is the bug. A route whose Update
// failed used to be skipped with `continue`, the middleware deleted anyway, and
// nil returned -- so the API reported success. The router resolves a route's
// middleware IDs with a plain store lookup and silently skips misses, so that
// route quietly lost the middleware. When it is the WAF or an auth middleware,
// the route is left unprotected and nothing says so.
func TestDeleteRefusesWhenARouteCannotBeUnlinked(t *testing.T) {
	t.Parallel()

	mwStore := newMwStore(&gateonv1.Middleware{Id: "waf-1", Type: "waf"})
	rtStore := &fakeRouteStore{
		routes: []*gateonv1.Route{
			{Id: "route-ok", Middlewares: []string{"waf-1"}},
			{Id: "route-bad", Middlewares: []string{"waf-1"}},
		},
		failFor: map[string]bool{"route-bad": true},
	}
	svc := newSvc(mwStore, rtStore, &fakeInvalidator{}, &fakeWAFInvalidator{})

	err := svc.DeleteMiddleware(context.Background(), "waf-1")
	if err == nil {
		t.Fatal("DeleteMiddleware reported success while a route still referenced " +
			"the middleware; that route is now silently unprotected")
	}
	if !strings.Contains(err.Error(), "route-bad") {
		t.Errorf("error = %q, want it to name the route that still references it", err)
	}
	if _, ok := mwStore.items["waf-1"]; !ok {
		t.Error("the middleware was deleted while a route still referenced it")
	}
}

func TestDeleteSucceedsWhenAllRoutesUnlink(t *testing.T) {
	t.Parallel()

	mwStore := newMwStore(&gateonv1.Middleware{Id: "mw-1", Type: "ratelimit"})
	rtStore := &fakeRouteStore{
		routes:  []*gateonv1.Route{{Id: "r1", Middlewares: []string{"mw-1", "other"}}},
		failFor: map[string]bool{},
	}
	inv := &fakeInvalidator{}
	svc := newSvc(mwStore, rtStore, inv, &fakeWAFInvalidator{})

	if err := svc.DeleteMiddleware(context.Background(), "mw-1"); err != nil {
		t.Fatalf("DeleteMiddleware: %v", err)
	}
	if _, ok := mwStore.items["mw-1"]; ok {
		t.Error("the middleware was not deleted")
	}
	if got := rtStore.routes[0].Middlewares; len(got) != 1 || got[0] != "other" {
		t.Errorf("route middlewares = %v, want just [other]", got)
	}
	if len(inv.routes) != 1 || inv.routes[0] != "r1" {
		t.Errorf("invalidated routes = %v, want [r1]", inv.routes)
	}
}

// TestDeleteDropsTheWAFCacheWhenTheTypeIsUnknown covers the second half. The
// type came from a Get whose miss was discarded into a nil, which skipped the
// invalidation and left the deleted policy live in the WAF cache. An extra
// rebuild costs milliseconds; a missed one keeps enforcing a deleted rule.
func TestDeleteDropsTheWAFCacheWhenTheTypeIsUnknown(t *testing.T) {
	t.Parallel()

	mwStore := newMwStore(&gateonv1.Middleware{Id: "waf-1", Type: "waf"})
	mwStore.getMisses = true // Get cannot tell us the type.
	waf := &fakeWAFInvalidator{}
	svc := newSvc(mwStore, &fakeRouteStore{failFor: map[string]bool{}}, &fakeInvalidator{}, waf)

	if err := svc.DeleteMiddleware(context.Background(), "waf-1"); err != nil {
		t.Fatalf("DeleteMiddleware: %v", err)
	}
	if waf.calls == 0 {
		t.Error("the WAF cache was not invalidated when the middleware type " +
			"could not be read; a deleted policy stays live in cache")
	}
}

func TestDeleteDropsTheWAFCacheForAWAFMiddleware(t *testing.T) {
	t.Parallel()

	mwStore := newMwStore(&gateonv1.Middleware{Id: "waf-1", Type: "waf"})
	waf := &fakeWAFInvalidator{}
	svc := newSvc(mwStore, &fakeRouteStore{failFor: map[string]bool{}}, &fakeInvalidator{}, waf)

	if err := svc.DeleteMiddleware(context.Background(), "waf-1"); err != nil {
		t.Fatalf("DeleteMiddleware: %v", err)
	}
	if waf.calls != 1 {
		t.Errorf("WAF invalidations = %d, want 1", waf.calls)
	}
}

func TestDeleteRejectsAnEmptyID(t *testing.T) {
	t.Parallel()

	svc := newSvc(newMwStore(), &fakeRouteStore{failFor: map[string]bool{}}, &fakeInvalidator{}, nil)
	if err := svc.DeleteMiddleware(context.Background(), ""); err == nil {
		t.Error("DeleteMiddleware accepted an empty id")
	}
}

func TestSaveAssignsAnIDAndInvalidatesTheWAFCache(t *testing.T) {
	t.Parallel()

	mwStore := newMwStore()
	waf := &fakeWAFInvalidator{}
	svc := newSvc(mwStore, &fakeRouteStore{failFor: map[string]bool{}}, &fakeInvalidator{}, waf)

	mw := &gateonv1.Middleware{Type: "waf"}
	if err := svc.SaveMiddleware(context.Background(), mw); err != nil {
		t.Fatalf("SaveMiddleware: %v", err)
	}
	if mw.Id == "" {
		t.Error("SaveMiddleware did not assign an id")
	}
	if waf.calls != 1 {
		t.Errorf("WAF invalidations = %d, want 1 for a waf middleware", waf.calls)
	}
}

func TestSaveDoesNotInvalidateTheWAFCacheForOtherTypes(t *testing.T) {
	t.Parallel()

	waf := &fakeWAFInvalidator{}
	svc := newSvc(newMwStore(), &fakeRouteStore{failFor: map[string]bool{}}, &fakeInvalidator{}, waf)

	if err := svc.SaveMiddleware(context.Background(), &gateonv1.Middleware{Type: "cors"}); err != nil {
		t.Fatalf("SaveMiddleware: %v", err)
	}
	if waf.calls != 0 {
		t.Errorf("WAF invalidations = %d, want 0 for a non-waf middleware", waf.calls)
	}
}
