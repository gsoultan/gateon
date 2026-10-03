// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// tls_binding binds a session to the client certificate of a TLS connection
// (ADR 0046). On an entrypoint without TLS it can only refuse every session, so
// a route save that puts it there is refused, as is turning on the retired
// global switch that applied it with no secret to bind with.

func tlsBindingFixture(t *testing.T) *ApiService {
	t.Helper()
	ctx, dir := t.Context(), t.TempDir()
	eps := config.NewEntryPointRegistry(filepath.Join(dir, "entrypoints.json"))
	for _, ep := range []*gateonv1.EntryPoint{
		{Id: "web", Name: "Plain HTTP", Address: "127.0.0.1:8081", Type: gateonv1.EntryPoint_HTTP},
		{Id: "websecure", Address: "127.0.0.1:8443", Type: gateonv1.EntryPoint_HTTP, Tls: &gateonv1.TlsConfig{Enabled: true}},
		{Id: "tcp", Address: "127.0.0.1:8086", Type: gateonv1.EntryPoint_TCP},
	} {
		if err := eps.Update(ctx, ep); err != nil {
			t.Fatal(err)
		}
	}
	mws := config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json"))
	if err := mws.Update(ctx, &gateonv1.Middleware{Id: "bind", Name: "bind", Type: "tls_binding",
		Config: map[string]string{"secret": strings.Repeat("k", 32)}}); err != nil {
		t.Fatal(err)
	}
	svcs := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	if err := svcs.Update(ctx, &gateonv1.Service{Id: "svc", Name: "svc"}); err != nil {
		t.Fatal(err)
	}
	return NewApiService(ApiServiceConfig{
		EntryPoints: eps, Services: svcs, Middlewares: mws,
		Routes:  config.NewRouteRegistry(filepath.Join(dir, "routes.json")),
		Globals: config.NewGlobalRegistry(filepath.Join(dir, "global.json")),
	})
}

func TestRouteSaveRefusesTLSBindingOnAnEntrypointWithoutTLS(t *testing.T) {
	svc := tlsBindingFixture(t)
	for i, tc := range []struct {
		entrypoints []string
		refused     bool
	}{
		{[]string{"web"}, true},
		{nil, true}, // every entrypoint, the plain one among them
		{[]string{"websecure", "web"}, true},
		{[]string{"websecure"}, false},
		{[]string{"websecure", "tcp"}, false}, // L4 runs no HTTP middleware
	} {
		rt := &gateonv1.Route{Name: "app" + string(rune('a'+i)), Type: "http", ServiceId: "svc",
			Rule: "PathPrefix(`/app`)", Entrypoints: tc.entrypoints, Middlewares: []string{"bind"}}
		_, err := svc.UpdateRoute(withRole(auth.RoleAdmin), &gateonv1.UpdateRouteRequest{Route: rt})
		switch {
		case tc.refused && err == nil:
			t.Errorf("entrypoints %v: a tls_binding route was saved on an entrypoint without TLS", tc.entrypoints)
		case tc.refused && !strings.Contains(err.Error(), "no TLS"):
			t.Errorf("entrypoints %v: refusal %q does not say why", tc.entrypoints, err)
		case !tc.refused && err != nil:
			t.Errorf("entrypoints %v: refused: %v", tc.entrypoints, err)
		}
	}
}

func TestGlobalTLSBindingSwitchCannotBeTurnedOn(t *testing.T) {
	svc := tlsBindingFixture(t)
	update := &gateonv1.GlobalConfig{SecurityAdvanced: &gateonv1.SecurityAdvancedConfig{
		TlsBinding: &gateonv1.TlsBindingConfig{Enabled: true, CookieName: "session"},
	}}
	_, err := svc.UpdateGlobalConfig(withRole(auth.RoleAdmin), &gateonv1.UpdateGlobalConfigRequest{Config: update})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "retired") {
		t.Fatalf("turning the global TLS Session Binding on: err = %v, want InvalidArgument saying it is retired", err)
	}
	if svc.Globals.Get(t.Context()).GetSecurityAdvanced().GetTlsBinding().GetEnabled() {
		t.Fatal("the refused switch was stored")
	}
}
