// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package route

import (
	"context"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type fakeMiddlewareStore struct {
	config.MiddlewareStore
	mws map[string]*gateonv1.Middleware
}

func (f fakeMiddlewareStore) Get(_ context.Context, id string) (*gateonv1.Middleware, bool) {
	m, ok := f.mws[id]
	return m, ok
}

type fakeEntryPointStore struct {
	config.EntryPointStore
	eps []*gateonv1.EntryPoint
}

func (f fakeEntryPointStore) Get(_ context.Context, id string) (*gateonv1.EntryPoint, bool) {
	for _, ep := range f.eps {
		if ep.Id == id {
			return ep, true
		}
	}
	return nil, false
}

func (f fakeEntryPointStore) List(context.Context) []*gateonv1.EntryPoint { return f.eps }

func tlsBindingService(store config.RouteStore) Service {
	mws := fakeMiddlewareStore{mws: map[string]*gateonv1.Middleware{
		"bind": {Id: "bind", Type: "tls_binding"},
		"hdrs": {Id: "hdrs", Type: "headers"},
	}}
	eps := fakeEntryPointStore{eps: []*gateonv1.EntryPoint{
		{Id: "web", Type: gateonv1.EntryPoint_HTTP},
		{Id: "websecure", Name: "Secure", Type: gateonv1.EntryPoint_HTTP, Tls: &gateonv1.TlsConfig{Enabled: true}},
		{Id: "tcp", Type: gateonv1.EntryPoint_TCP},
	}}
	return NewService(store, &recordingInvalidator{}, nil, nil, NewTLSBindingCheck(mws, eps))
}

// TestSaveRouteRefusesTLSBindingWithoutTLS: tls_binding binds a session to a
// TLS client certificate (ADR 0046), so a route serving it over plain HTTP --
// named, or implied by naming no entrypoint -- is refused; and a nil guard
// passed beside it is skipped rather than called.
func TestSaveRouteRefusesTLSBindingWithoutTLS(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mws, eps    []string
		wantRefusal bool
	}{
		{"plain entrypoint", []string{"bind"}, []string{"web"}, true},
		{"every entrypoint", []string{"bind"}, nil, true},
		{"tls entrypoint", []string{"bind"}, []string{"websecure"}, false},
		{"tls and l4", []string{"bind"}, []string{"websecure", "tcp"}, false},
		{"no tls_binding", []string{"hdrs"}, []string{"web"}, false},
		{"unknown entrypoint", []string{"bind"}, []string{"gone"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeRouteStore()
			err := tlsBindingService(store).SaveRoute(context.Background(), &gateonv1.Route{
				Name: "r", ServiceId: "svc", Rule: "PathPrefix(`/a`)", Middlewares: tc.mws, Entrypoints: tc.eps,
			})
			if tc.wantRefusal {
				if err == nil || !strings.Contains(err.Error(), "no TLS") {
					t.Fatalf("err = %v, want a refusal saying the entrypoint has no TLS", err)
				}
				if len(store.saved) != 0 {
					t.Fatal("the refused route was stored")
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
}

// TestTLSBindingCheckWithoutStoresAllowsTheSave: a check built without its
// stores (a build that does not wire them) checks nothing rather than panic.
func TestTLSBindingCheckWithoutStoresAllowsTheSave(t *testing.T) {
	var nilCheck *TLSBindingCheck
	rt := &gateonv1.Route{Middlewares: []string{"bind"}}
	for _, c := range []*TLSBindingCheck{nilCheck, NewTLSBindingCheck(nil, nil)} {
		if err := c.AuthorizeRouteSave(context.Background(), rt); err != nil {
			t.Fatalf("err = %v", err)
		}
	}
}
