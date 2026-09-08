// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package route

import (
	"context"
	"errors"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type fakeRouteStore struct {
	config.RouteStore
	saved     map[string]*gateonv1.Route
	deleted   []string
	updateErr error
	deleteErr error
}

func newFakeRouteStore() *fakeRouteStore {
	return &fakeRouteStore{saved: map[string]*gateonv1.Route{}}
}
func (f *fakeRouteStore) Update(_ context.Context, rt *gateonv1.Route) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	f.saved[rt.Id] = rt
	return nil
}
func (f *fakeRouteStore) Delete(_ context.Context, id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, id)
	return nil
}

type recordingInvalidator struct{ routes []string }

func (r *recordingInvalidator) InvalidateRoute(id string)                   { r.routes = append(r.routes, id) }
func (r *recordingInvalidator) InvalidateRoutes(func(*gateonv1.Route) bool) {}
func (r *recordingInvalidator) InvalidateTLS()                              {}
func (r *recordingInvalidator) InvalidateWAF()                              {}

// TestSaveRouteRequiresAService covers the check that keeps a route routable.
//
// A route with no service has nowhere to send anything. Stored, it appears in
// the dashboard as configured and answers every request with an error.
func TestSaveRouteRequiresAService(t *testing.T) {
	store := newFakeRouteStore()
	s := NewService(store, &recordingInvalidator{}, nil)

	err := s.SaveRoute(context.Background(), &gateonv1.Route{Rule: "PathPrefix(`/a`)"})
	if err == nil {
		t.Error("a route with no service_id was accepted")
	}
	if len(store.saved) != 0 {
		t.Error("it was stored anyway")
	}
}

// TestSaveRouteRequiresARuleExceptForL4 pins the exception.
//
// An HTTP route with no rule matches nothing, so storing it is storing a route
// that cannot serve. A TCP or UDP route is matched by entrypoint instead, which
// is why the same check would make L4 routes impossible to create.
func TestSaveRouteRequiresARuleExceptForL4(t *testing.T) {
	for _, tc := range []struct {
		typ     string
		wantErr bool
	}{
		{"", true},     // http by default
		{"http", true}, //
		{"grpc", true}, //
		{"tcp", false}, // matched by entrypoint
		{"udp", false}, //
		{"TCP", false}, // case must not decide it
		{"Udp", false}, //
	} {
		t.Run("type="+tc.typ, func(t *testing.T) {
			s := NewService(newFakeRouteStore(), &recordingInvalidator{}, nil)
			err := s.SaveRoute(context.Background(),
				&gateonv1.Route{ServiceId: "svc-1", Type: tc.typ})
			if (err != nil) != tc.wantErr {
				t.Errorf("type %q gave error %v, wantErr %v", tc.typ, err, tc.wantErr)
			}
		})
	}
}

// TestSaveRouteAssignsAnIDAndInvalidates covers the create path.
func TestSaveRouteAssignsAnIDAndInvalidates(t *testing.T) {
	store, inv := newFakeRouteStore(), &recordingInvalidator{}
	s := NewService(store, inv, nil)

	rt := &gateonv1.Route{ServiceId: "svc-1", Rule: "PathPrefix(`/a`)"}
	if err := s.SaveRoute(context.Background(), rt); err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}
	if rt.Id == "" {
		t.Fatal("no id was assigned; the next save would create a second route")
	}
	if len(inv.routes) != 1 || inv.routes[0] != rt.Id {
		t.Errorf("invalidated %v, want the saved route. Without it the gateway keeps "+
			"serving the previous version of this route from a cached chain.",
			inv.routes)
	}
}

// TestSaveRouteDoesNotInvalidateWhenTheStoreFails is the ordering that matters.
//
// Invalidating after a failed write would discard a working chain and rebuild it
// from configuration that did not change — churn caused by an edit that was
// rejected.
func TestSaveRouteDoesNotInvalidateWhenTheStoreFails(t *testing.T) {
	store, inv := newFakeRouteStore(), &recordingInvalidator{}
	store.updateErr = errors.New("disk full")

	err := NewService(store, inv, nil).SaveRoute(context.Background(),
		&gateonv1.Route{ServiceId: "svc-1", Rule: "PathPrefix(`/a`)"})
	if err == nil {
		t.Fatal("a failed store write was reported as success")
	}
	if len(inv.routes) != 0 {
		t.Errorf("invalidated %v after the write failed", inv.routes)
	}
}

// TestDeleteRouteInvalidates covers the delete path.
//
// A deleted route whose proxy is not invalidated keeps serving from the cached
// chain — the route is gone from the configuration and still answering.
func TestDeleteRouteInvalidates(t *testing.T) {
	store, inv := newFakeRouteStore(), &recordingInvalidator{}
	s := NewService(store, inv, nil)

	if err := s.DeleteRoute(context.Background(), "route-a"); err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}
	if len(store.deleted) != 1 {
		t.Error("the route was not deleted")
	}
	if len(inv.routes) != 1 || inv.routes[0] != "route-a" {
		t.Errorf("invalidated %v, want route-a; otherwise a deleted route keeps "+
			"answering from its cached chain", inv.routes)
	}
}

// TestDeleteRouteRefusesAnEmptyID and does not invalidate on failure.
func TestDeleteRouteRefusesAnEmptyID(t *testing.T) {
	store, inv := newFakeRouteStore(), &recordingInvalidator{}
	s := NewService(store, inv, nil)

	if err := s.DeleteRoute(context.Background(), ""); err == nil {
		t.Error("an empty id was accepted")
	}
	if len(store.deleted) != 0 || len(inv.routes) != 0 {
		t.Errorf("deleted %v / invalidated %v on an empty id", store.deleted, inv.routes)
	}

	store.deleteErr = errors.New("nope")
	if err := s.DeleteRoute(context.Background(), "route-a"); err == nil {
		t.Error("a failed delete was reported as success")
	}
	if len(inv.routes) != 0 {
		t.Errorf("invalidated %v after the delete failed", inv.routes)
	}
}
