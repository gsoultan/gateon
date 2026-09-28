// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package route

import (
	"context"
	"errors"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type fakeRouteGuard struct {
	err    error
	called bool
	saw    *gateonv1.Route
}

func (g *fakeRouteGuard) AuthorizeRouteSave(_ context.Context, r *gateonv1.Route) error {
	g.called = true
	g.saw = r
	return g.err
}

// A SaveGuard authorizes a route save before it persists; a refusal stores
// nothing. It runs after the id is assigned, so it sees the route it will save.
func TestSaveRouteRefusedByTheGuardStoresNothing(t *testing.T) {
	store := newFakeRouteStore()
	guard := &fakeRouteGuard{err: errors.New("needs an administrator")}
	s := NewService(store, &recordingInvalidator{}, nil, guard)

	err := s.SaveRoute(context.Background(), &gateonv1.Route{ServiceId: "svc-1", Rule: "PathPrefix(`/a`)"})
	if err == nil || !errors.Is(err, guard.err) {
		t.Fatalf("SaveRoute error = %v, want the guard's refusal", err)
	}
	if !guard.called {
		t.Error("the guard was not consulted")
	}
	if len(store.saved) != 0 {
		t.Error("a route the guard refused was stored")
	}
}

func TestSaveRouteAllowedByTheGuardIsStored(t *testing.T) {
	store := newFakeRouteStore()
	guard := &fakeRouteGuard{}
	s := NewService(store, &recordingInvalidator{}, nil, guard)

	rt := &gateonv1.Route{ServiceId: "svc-1", Rule: "PathPrefix(`/a`)"}
	if err := s.SaveRoute(context.Background(), rt); err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}
	if !guard.called || guard.saw == nil || guard.saw.Id == "" {
		t.Errorf("the guard saw %+v, want the route with its id assigned", guard.saw)
	}
	if len(store.saved) != 1 {
		t.Error("an allowed route was not stored")
	}
}
