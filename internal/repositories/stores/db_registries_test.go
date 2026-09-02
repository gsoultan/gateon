// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package stores

import (
	"context"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// db_routes_test.go covered routes. Entrypoints, middlewares, services and TLS
// options had no tests at all, and they decide the same thing routes do: what
// configuration the gateway believes it has after a restart.
//
// Every round trip below builds a *second* registry against the same database,
// because construction is where loadFromDB runs. Reading back through the
// registry that just wrote is only reading its own memory, which would pass
// whether or not anything reached storage.

func TestEntryPointRegistry_RoundTripsThroughARestart(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()

	want := &gateonv1.EntryPoint{
		Id:      "ep-1",
		Name:    "websecure",
		Address: ":443",
		Type:    gateonv1.EntryPoint_HTTP,
	}
	if err := NewDBEntryPointRegistry(database, dialect).Update(ctx, want); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, ok := NewDBEntryPointRegistry(database, dialect).Get(ctx, want.Id)
	if !ok {
		t.Fatal("entrypoint did not survive the restart")
	}
	if got.Name != want.Name || got.Address != want.Address || got.Type != want.Type {
		t.Errorf("got %+v, want name=%q address=%q type=%v", got, want.Name, want.Address, want.Type)
	}
}

func TestMiddlewareRegistry_RoundTripsThroughARestart(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()

	want := &gateonv1.Middleware{
		Id:     "mw-1",
		Name:   "waf",
		Type:   "waf",
		Config: map[string]string{"tier": "standard", "audit_only": "false"},
	}
	if err := NewDBMiddlewareRegistry(database, dialect).Update(ctx, want); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, ok := NewDBMiddlewareRegistry(database, dialect).Get(ctx, want.Id)
	if !ok {
		t.Fatal("middleware did not survive the restart")
	}
	if got.Name != want.Name || got.Type != want.Type {
		t.Errorf("got name=%q type=%q, want %q/%q", got.Name, got.Type, want.Name, want.Type)
	}
	// The config map is what the middleware actually does; losing a key here
	// silently changes behaviour rather than removing the middleware.
	for k, v := range want.Config {
		if got.Config[k] != v {
			t.Errorf("config[%q] = %q, want %q", k, got.Config[k], v)
		}
	}
}

func TestServiceRegistry_RoundTripsThroughARestart(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()

	want := &gateonv1.Service{
		Id:                 "svc-1",
		Name:               "api-backend",
		BackendType:        "http",
		LoadBalancerPolicy: "round_robin",
		HealthCheckPath:    "/healthz",
	}
	if err := NewDBServiceRegistry(database, dialect).Update(ctx, want); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, ok := NewDBServiceRegistry(database, dialect).Get(ctx, want.Id)
	if !ok {
		t.Fatal("service did not survive the restart")
	}
	if got.Name != want.Name || got.BackendType != want.BackendType {
		t.Errorf("got name=%q backend=%q, want %q/%q", got.Name, got.BackendType, want.Name, want.BackendType)
	}
	// The policy decides how traffic is spread; losing it silently changes
	// balancing rather than removing the service.
	if got.LoadBalancerPolicy != want.LoadBalancerPolicy {
		t.Errorf("LoadBalancerPolicy = %q, want %q", got.LoadBalancerPolicy, want.LoadBalancerPolicy)
	}
}

func TestTLSOptionRegistry_RoundTripsThroughARestart(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()

	want := &gateonv1.TLSOption{
		Id:                 "tls-1",
		Name:               "modern",
		MinTlsVersion:      "TLS1.2",
		MaxTlsVersion:      "TLS1.3",
		CipherSuites:       []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
		AlpnProtocols:      []string{"h2", "http/1.1"},
		ClientAuthorityIds: []string{"ca-1", "ca-2"},
		SniStrict:          true,
	}
	if err := NewDBTLSOptionRegistry(database, dialect).Update(ctx, want); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, ok := NewDBTLSOptionRegistry(database, dialect).Get(ctx, want.Id)
	if !ok {
		t.Fatal("TLS option did not survive the restart")
	}
	// These three are the comma-joined columns. A member arriving split, or a
	// list arriving short, changes which ciphers the gateway will negotiate.
	if len(got.CipherSuites) != 2 || got.CipherSuites[0] != want.CipherSuites[0] {
		t.Errorf("CipherSuites = %v, want %v", got.CipherSuites, want.CipherSuites)
	}
	if len(got.AlpnProtocols) != 2 {
		t.Errorf("AlpnProtocols = %v, want %v", got.AlpnProtocols, want.AlpnProtocols)
	}
	if len(got.ClientAuthorityIds) != 2 {
		t.Errorf("ClientAuthorityIds = %v, want %v", got.ClientAuthorityIds, want.ClientAuthorityIds)
	}
	if !got.SniStrict {
		t.Error("SniStrict was lost, so strict SNI checking would silently stop")
	}
}

// TestCommaIsRejectedAtEveryCallSite guards the wiring, not joinListColumn.
//
// The helper is already fully covered and would stay so if a call site stopped
// using it. These drive Update, which is where an API-supplied name with a comma
// would otherwise be written and read back as two entries -- a route gaining a
// middleware nobody configured, or a TLS option negotiating a cipher list
// nobody chose.
func TestCommaIsRejectedAtEveryCallSite(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()

	t.Run("route entrypoints", func(t *testing.T) {
		rt := sampleRoute()
		rt.Entrypoints = []string{"web,websecure"}
		assertCommaRejected(t, NewDBRouteRegistry(database, dialect).Update(ctx, rt), "entrypoint name")
	})

	t.Run("route middlewares", func(t *testing.T) {
		rt := sampleRoute()
		rt.Middlewares = []string{"waf,ratelimit"}
		assertCommaRejected(t, NewDBRouteRegistry(database, dialect).Update(ctx, rt), "middleware name")
	})

	t.Run("tls cipher suites", func(t *testing.T) {
		opt := &gateonv1.TLSOption{Id: "t", Name: "n", CipherSuites: []string{"A,B"}}
		assertCommaRejected(t, NewDBTLSOptionRegistry(database, dialect).Update(ctx, opt), "cipher suite")
	})

	t.Run("tls alpn protocols", func(t *testing.T) {
		opt := &gateonv1.TLSOption{Id: "t", Name: "n", AlpnProtocols: []string{"h2,http/1.1"}}
		assertCommaRejected(t, NewDBTLSOptionRegistry(database, dialect).Update(ctx, opt), "ALPN protocol")
	})

	t.Run("tls client authority ids", func(t *testing.T) {
		opt := &gateonv1.TLSOption{Id: "t", Name: "n", ClientAuthorityIds: []string{"ca-1,ca-2"}}
		assertCommaRejected(t, NewDBTLSOptionRegistry(database, dialect).Update(ctx, opt), "client authority ID")
	})
}

func assertCommaRejected(t *testing.T, err error, wantField string) {
	t.Helper()
	if err == nil {
		t.Fatalf("a value containing a comma was accepted; it would be read back as two %ss", wantField)
	}
	if !strings.Contains(err.Error(), wantField) {
		t.Errorf("error %q does not name %q, so it does not say which field to fix", err, wantField)
	}
}

// Delete must match the id exactly. A prefix or LIKE match would remove records
// whose ids merely start the same, and the caller would see a successful delete.
func TestDeleteRemovesOnlyTheNamedRecord(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()

	keep := &gateonv1.EntryPoint{Id: "ep", Name: "keep", Address: ":80", Type: gateonv1.EntryPoint_HTTP}
	remove := &gateonv1.EntryPoint{Id: "ep-2", Name: "remove", Address: ":81", Type: gateonv1.EntryPoint_HTTP}

	reg := NewDBEntryPointRegistry(database, dialect)
	if err := reg.Update(ctx, keep); err != nil {
		t.Fatalf("update keep: %v", err)
	}
	if err := reg.Update(ctx, remove); err != nil {
		t.Fatalf("update remove: %v", err)
	}
	if err := reg.Delete(ctx, remove.Id); err != nil {
		t.Fatalf("delete: %v", err)
	}

	fresh := NewDBEntryPointRegistry(database, dialect)
	if _, ok := fresh.Get(ctx, remove.Id); ok {
		t.Error("the deleted entrypoint came back after a restart")
	}
	if _, ok := fresh.Get(ctx, keep.Id); !ok {
		t.Error(`deleting "ep-2" also removed "ep", so the delete is not matching exactly`)
	}
}
