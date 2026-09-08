// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type fakeEPStore struct {
	config.EntryPointStore
	saved     map[string]*gateonv1.EntryPoint
	deleted   []string
	updateErr error
}

func newFakeEPStore() *fakeEPStore {
	return &fakeEPStore{saved: map[string]*gateonv1.EntryPoint{}}
}
func (f *fakeEPStore) Update(_ context.Context, ep *gateonv1.EntryPoint) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	f.saved[ep.Id] = ep
	return nil
}
func (f *fakeEPStore) Delete(_ context.Context, id string) error {
	f.deleted = append(f.deleted, id)
	return nil
}

// TestSaveEntryPointRequiresAnAddress covers the one thing it validates.
//
// An entrypoint with no address is a listener bound to nothing. Storing it makes
// the dashboard show a configured entrypoint that never accepts a connection.
func TestSaveEntryPointRequiresAnAddress(t *testing.T) {
	store := newFakeEPStore()
	s := NewService(store, nil, nil)

	if err := s.SaveEntryPoint(context.Background(), &gateonv1.EntryPoint{}); err == nil {
		t.Error("an entrypoint with no address was accepted")
	}
	if len(store.saved) != 0 {
		t.Error("it was stored anyway")
	}
}

// TestSaveEntryPointAssignsAnID covers the create path.
func TestSaveEntryPointAssignsAnID(t *testing.T) {
	store := newFakeEPStore()
	s := NewService(store, nil, nil)

	ep := &gateonv1.EntryPoint{Address: ":8080"}
	if err := s.SaveEntryPoint(context.Background(), ep); err != nil {
		t.Fatalf("SaveEntryPoint: %v", err)
	}
	if ep.Id == "" {
		t.Error("no id was assigned; a later save would create a second entrypoint " +
			"instead of updating this one")
	}

	// An existing id is preserved, or every edit forks a new entrypoint.
	existing := &gateonv1.EntryPoint{Id: "web", Address: ":80"}
	if err := s.SaveEntryPoint(context.Background(), existing); err != nil {
		t.Fatalf("SaveEntryPoint: %v", err)
	}
	if existing.Id != "web" {
		t.Errorf("id became %q; an edit must update the entrypoint, not fork it", existing.Id)
	}
}

// TestSaveEntryPointInfersType covers the inference, which decides how the
// listener is served.
func TestSaveEntryPointInfersType(t *testing.T) {
	for _, tc := range []struct {
		name string
		ep   *gateonv1.EntryPoint
		want gateonv1.EntryPoint_Type
	}{
		{"port 80 is HTTP", &gateonv1.EntryPoint{Address: ":80"}, gateonv1.EntryPoint_HTTP},
		{"port 443 is HTTP", &gateonv1.EntryPoint{Address: ":443"}, gateonv1.EntryPoint_HTTP},
		{"port 8080 is HTTP", &gateonv1.EntryPoint{Address: ":8080"}, gateonv1.EntryPoint_HTTP},
		{"an arbitrary port is TCP", &gateonv1.EntryPoint{Address: ":9000"}, gateonv1.EntryPoint_TCP},
		{"TLS makes it HTTP whatever the port",
			&gateonv1.EntryPoint{Address: ":9000", Tls: &gateonv1.TlsConfig{Enabled: true}},
			gateonv1.EntryPoint_HTTP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewService(newFakeEPStore(), nil, nil)
			if err := s.SaveEntryPoint(context.Background(), tc.ep); err != nil {
				t.Fatalf("SaveEntryPoint: %v", err)
			}
			if tc.ep.Type != tc.want {
				t.Errorf("type = %v, want %v; the type decides which server is put "+
					"in front of the listener", tc.ep.Type, tc.want)
			}
		})
	}
}

// TestSaveEntryPointDefaultsToTCP covers the protocol fallback.
//
// An entrypoint with no protocol would otherwise be bound for neither, which is
// a listener that exists and accepts nothing.
func TestSaveEntryPointDefaultsToTCP(t *testing.T) {
	ep := &gateonv1.EntryPoint{Address: ":9000"}
	if err := NewService(newFakeEPStore(), nil, nil).SaveEntryPoint(context.Background(), ep); err != nil {
		t.Fatalf("SaveEntryPoint: %v", err)
	}
	var hasTCP bool
	for _, p := range ep.Protocols {
		if p == gateonv1.EntryPoint_TCP_PROTO {
			hasTCP = true
		}
	}
	if !hasTCP {
		t.Errorf("protocols = %v, want TCP added by default", ep.Protocols)
	}
}

// TestDeleteEntryPointRefusesAnEmptyID covers the guard.
func TestDeleteEntryPointRefusesAnEmptyID(t *testing.T) {
	store := newFakeEPStore()
	if err := NewService(store, nil, nil).DeleteEntryPoint(context.Background(), ""); err == nil {
		t.Error("an empty id was accepted")
	}
	if len(store.deleted) != 0 {
		t.Errorf("it deleted %v", store.deleted)
	}
}

// TestDeleteEntryPointDoesNotCascadeToRoutes guards against a change that looks
// like a tidy-up and is a hole.
//
// Deleting a service clears its id from every route that referenced it. Applying
// the same symmetry here would publish routes rather than tidy them.
// Route.Entrypoints is a filter the router applies only when it is non-empty --
// `if len(rt.Entrypoints) > 0` -- so an empty list means the route serves on
// *every* entrypoint. Clearing the reference on a route bound solely to an
// internal listener would put it on the public one, immediately, as a side
// effect of a delete, and the operator's last action was a deletion, which is
// the last place anyone looks for a route that became reachable.
//
// Leaving the id dangling fails closed: the filter matches no live entrypoint,
// so the route goes quiet. Quiet is the recoverable half.
//
// Checked by whether this service can reach routes at all. A route store here
// means someone is about to write that cascade -- which is the moment to read
// the paragraph above. The invalidator is not that: it discards cached chains
// and never edits a route.
func TestDeleteEntryPointDoesNotCascadeToRoutes(t *testing.T) {
	impl, ok := NewService(newFakeEPStore(), nil, nil).(*serviceImpl)
	if !ok {
		t.Fatal("NewService no longer returns *serviceImpl; re-read the reasoning " +
			"above before adjusting this test")
	}

	v := reflect.Indirect(reflect.ValueOf(impl))
	routeStoreType := reflect.TypeOf((*config.RouteStore)(nil)).Elem()
	for i := range v.NumField() {
		ft := v.Type().Field(i)
		if ft.Type == routeStoreType || ft.Type.Implements(routeStoreType) {
			t.Errorf("serviceImpl now holds a route store (field %q).\n"+
				"If this is for clearing Route.Entrypoints on delete: the router "+
				"only applies that filter when the list is non-empty, so clearing "+
				"it publishes an internally-bound route on every entrypoint.",
				ft.Name)
		}
	}
}

// TestSaveEntryPointInvalidatesAffectedRoutes is the divergence this package was
// on the wrong side of.
//
// Saving an entrypoint was implemented twice: internal/api invalidated the route
// chains the change affects, and this package -- which is what the dashboard's
// PUT /v1/entryPoints goes through -- did nothing. An operator tightening an
// entrypoint's TLS in the dashboard got a success and a listener still
// negotiating the old configuration until restart.
func TestSaveEntryPointInvalidatesAffectedRoutes(t *testing.T) {
	inv := &recordingInvalidator{}
	s := NewService(newFakeEPStore(), inv, nil)

	if err := s.SaveEntryPoint(context.Background(),
		&gateonv1.EntryPoint{Id: "web", Address: ":80"}); err != nil {
		t.Fatalf("SaveEntryPoint: %v", err)
	}
	if inv.routePredicate == nil {
		t.Fatal("no routes were invalidated; the chains built against this " +
			"entrypoint keep serving the configuration it just replaced")
	}

	// Bound to this entrypoint.
	if !inv.routePredicate(&gateonv1.Route{Entrypoints: []string{"web"}}) {
		t.Error("a route bound to the saved entrypoint was not invalidated")
	}
	// Global: no entrypoints listed means it serves on every one, including this.
	if !inv.routePredicate(&gateonv1.Route{Entrypoints: nil}) {
		t.Error("a global route was not invalidated; an empty entrypoint list " +
			"means the route serves on every entrypoint, so this change affects it")
	}
	// Bound elsewhere: untouched.
	if inv.routePredicate(&gateonv1.Route{Entrypoints: []string{"other"}}) {
		t.Error("a route bound to a different entrypoint was invalidated")
	}
}

// TestSaveEntryPointInvalidatesTLSOnlyWhenItHasTLS covers the second half.
//
// Rebuilding every listener's TLS on an entrypoint save that had nothing to do
// with TLS is churn across the whole gateway.
func TestSaveEntryPointInvalidatesTLSOnlyWhenItHasTLS(t *testing.T) {
	withTLS := &recordingInvalidator{}
	if err := NewService(newFakeEPStore(), withTLS, nil).SaveEntryPoint(context.Background(),
		&gateonv1.EntryPoint{Id: "websecure", Address: ":443",
			Tls: &gateonv1.TlsConfig{Enabled: true}}); err != nil {
		t.Fatalf("SaveEntryPoint: %v", err)
	}
	if withTLS.tls != 1 {
		t.Errorf("InvalidateTLS called %d times for an entrypoint carrying TLS "+
			"config, want 1 — otherwise the listener keeps the old settings",
			withTLS.tls)
	}

	plain := &recordingInvalidator{}
	if err := NewService(newFakeEPStore(), plain, nil).SaveEntryPoint(context.Background(),
		&gateonv1.EntryPoint{Id: "web", Address: ":80"}); err != nil {
		t.Fatalf("SaveEntryPoint: %v", err)
	}
	if plain.tls != 0 {
		t.Errorf("InvalidateTLS called %d times for an entrypoint with no TLS "+
			"config; that rebuilds TLS across the gateway for an unrelated change",
			plain.tls)
	}
}

// TestSaveEntryPointDoesNotInvalidateWhenTheStoreFails pins the ordering.
func TestSaveEntryPointDoesNotInvalidateWhenTheStoreFails(t *testing.T) {
	store := newFakeEPStore()
	store.updateErr = errors.New("disk full")
	inv := &recordingInvalidator{}

	if err := NewService(store, inv, nil).SaveEntryPoint(context.Background(),
		&gateonv1.EntryPoint{Id: "web", Address: ":80"}); err == nil {
		t.Fatal("a failed store write was reported as success")
	}
	if inv.routePredicate != nil || inv.tls != 0 {
		t.Error("chains were discarded after a write that did not happen")
	}
}

// recordingInvalidator keeps the predicate so a test can ask which routes it
// would have matched, rather than only how many times it was called.
type recordingInvalidator struct {
	routePredicate func(*gateonv1.Route) bool
	tls            int
}

func (r *recordingInvalidator) InvalidateRoute(string) {}
func (r *recordingInvalidator) InvalidateRoutes(f func(*gateonv1.Route) bool) {
	r.routePredicate = f
}
func (r *recordingInvalidator) InvalidateTLS() { r.tls++ }
func (r *recordingInvalidator) InvalidateWAF() {}
