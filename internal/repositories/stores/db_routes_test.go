// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package stores

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// internal/repositories/stores had no tests. It is the layer that decides what
// the gateway believes its own configuration is, so a silent failure here does
// not corrupt one record — it changes what traffic the gateway serves.

func newTestDB(t *testing.T) (*sql.DB, db.Dialect) {
	t.Helper()
	dsn := "sqlite:" + filepath.Join(t.TempDir(), "stores_test.db")
	database, dialect, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := db.Migrate(database, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return database, dialect
}

func sampleRoute() *gateonv1.Route {
	return &gateonv1.Route{
		Id:          "route-1",
		Name:        "api",
		Type:        "http",
		Entrypoints: []string{"web", "websecure"},
		Rule:        "Host(`example.com`) && PathPrefix(`/api`)",
		Priority:    42,
		Middlewares: []string{"waf", "ratelimit"},
		ServiceId:   "svc-1",
		Disabled:    false,
	}
}

// The load path runs at construction, so a route that does not survive the
// round trip is a route the gateway silently stops serving after a restart.
func TestDBRouteRegistry_RoundTripsThroughTheDatabase(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()

	want := sampleRoute()
	if err := NewDBRouteRegistry(database, dialect).Update(ctx, want); err != nil {
		t.Fatalf("update: %v", err)
	}

	// A fresh registry reads it back from disk the way a restart would.
	got := NewDBRouteRegistry(database, dialect).Routes()[want.Id]
	if got == nil {
		t.Fatal("route did not survive the reload")
	}
	if got.Name != want.Name || got.Type != want.Type || got.Rule != want.Rule {
		t.Fatalf("scalar fields differ: got %+v", got)
	}
	if got.Priority != want.Priority {
		t.Fatalf("Priority = %d, want %d", got.Priority, want.Priority)
	}
	if got.ServiceId != want.ServiceId {
		t.Fatalf("ServiceId = %q, want %q", got.ServiceId, want.ServiceId)
	}
	if len(got.Entrypoints) != 2 || got.Entrypoints[0] != "web" || got.Entrypoints[1] != "websecure" {
		t.Fatalf("Entrypoints = %v, want [web websecure]", got.Entrypoints)
	}
	if len(got.Middlewares) != 2 || got.Middlewares[0] != "waf" || got.Middlewares[1] != "ratelimit" {
		t.Fatalf("Middlewares = %v, want [waf ratelimit]", got.Middlewares)
	}
}

// TLS travels as JSON in its own column; losing it downgrades a route to
// plaintext, which is a security change rather than a formatting one.
func TestDBRouteRegistry_PreservesTLSConfig(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()

	rt := sampleRoute()
	rt.Tls = &gateonv1.RouteTLSConfig{
		CertificateIds: []string{"cert-a", "cert-b"},
		OptionId:       "modern",
		AcmeEnabled:    true,
	}
	if err := NewDBRouteRegistry(database, dialect).Update(ctx, rt); err != nil {
		t.Fatalf("update: %v", err)
	}

	got := NewDBRouteRegistry(database, dialect).Routes()[rt.Id]
	if got == nil || got.Tls == nil {
		t.Fatal("TLS config did not survive the reload; the route silently became plaintext")
	}
	if got.Tls.OptionId != "modern" || !got.Tls.AcmeEnabled {
		t.Fatalf("TLS = %+v, want OptionId=modern AcmeEnabled=true", got.Tls)
	}
	if len(got.Tls.CertificateIds) != 2 {
		t.Fatalf("CertificateIds = %v, want 2 entries", got.Tls.CertificateIds)
	}
}

// A route with no entrypoints or middlewares must come back with none, not with
// one empty-string entry that no entrypoint will ever match.
func TestDBRouteRegistry_EmptyListsStayEmpty(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()

	rt := sampleRoute()
	rt.Entrypoints = nil
	rt.Middlewares = nil
	if err := NewDBRouteRegistry(database, dialect).Update(ctx, rt); err != nil {
		t.Fatalf("update: %v", err)
	}

	got := NewDBRouteRegistry(database, dialect).Routes()[rt.Id]
	if len(got.Entrypoints) != 0 {
		t.Fatalf("Entrypoints = %v, want empty", got.Entrypoints)
	}
	if len(got.Middlewares) != 0 {
		t.Fatalf("Middlewares = %v, want empty", got.Middlewares)
	}
}

// Entrypoints and middlewares are stored comma-joined in a single column, so a
// name containing a comma comes back as two names. Update rejects it rather
// than writing a value the load path cannot read back — the alternative is
// silent corruption, where a route quietly gains a middleware nobody
// configured, or loses the one that was protecting it.
func TestDBRouteRegistry_RejectsCommaInListMembers(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()
	reg := NewDBRouteRegistry(database, dialect)

	t.Run("entrypoint", func(t *testing.T) {
		rt := sampleRoute()
		rt.Entrypoints = []string{"web,websecure"}
		if err := reg.Update(ctx, rt); err == nil {
			t.Fatal("a comma in an entrypoint name must be rejected, not split on reload")
		}
	})

	t.Run("middleware", func(t *testing.T) {
		rt := sampleRoute()
		rt.Middlewares = []string{"waf,ratelimit"}
		if err := reg.Update(ctx, rt); err == nil {
			t.Fatal("a comma in a middleware name must be rejected, not split on reload")
		}
	})

	t.Run("rejection leaves nothing behind", func(t *testing.T) {
		var n int
		if err := database.QueryRow("SELECT COUNT(*) FROM routes").Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 0 {
			t.Fatalf("got %d rows, want 0: a rejected update must not write", n)
		}
	})
}

func TestDBRouteRegistry_UpdateOverwritesInPlace(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()
	reg := NewDBRouteRegistry(database, dialect)

	rt := sampleRoute()
	if err := reg.Update(ctx, rt); err != nil {
		t.Fatalf("update: %v", err)
	}
	rt.Rule = "Host(`changed.example.com`)"
	if err := reg.Update(ctx, rt); err != nil {
		t.Fatalf("second update: %v", err)
	}

	var n int
	if err := database.QueryRow("SELECT COUNT(*) FROM routes").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("got %d rows, want 1: updating an existing id must not insert a duplicate", n)
	}
	if got := NewDBRouteRegistry(database, dialect).Routes()[rt.Id]; got.Rule != rt.Rule {
		t.Fatalf("Rule = %q, want %q", got.Rule, rt.Rule)
	}
}

func TestDBRouteRegistry_DeleteRemovesFromBothStoreAndMemory(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()
	reg := NewDBRouteRegistry(database, dialect)

	rt := sampleRoute()
	if err := reg.Update(ctx, rt); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := reg.Delete(ctx, rt.Id); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, still := reg.Routes()[rt.Id]; still {
		t.Fatal("route still present in memory after delete")
	}
	if got := NewDBRouteRegistry(database, dialect).Routes()[rt.Id]; got != nil {
		t.Fatal("route came back after a reload; the delete did not reach the database")
	}
}

// Priority drives route ordering, so it has to survive as a number rather than
// being coerced through a string column.
func TestDBRouteRegistry_PreservesPriorityIncludingNegative(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()
	reg := NewDBRouteRegistry(database, dialect)

	for _, p := range []int32{-100, 0, 1, 32767} {
		rt := sampleRoute()
		rt.Id = "route-p"
		rt.Priority = p
		if err := reg.Update(ctx, rt); err != nil {
			t.Fatalf("update(%d): %v", p, err)
		}
		if got := NewDBRouteRegistry(database, dialect).Routes()[rt.Id]; got.Priority != p {
			t.Fatalf("Priority = %d, want %d", got.Priority, p)
		}
	}
}
