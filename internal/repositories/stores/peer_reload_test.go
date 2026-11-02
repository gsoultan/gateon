// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package stores

import (
	"context"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Two gateways on one database each read it once, at start-up. A route one
// of them wrote, or deleted, was never seen by the other until it restarted.
// Reload takes the database as it is now: what a peer wrote appears, and what
// it deleted goes.
func TestAPeersRouteChangeIsSeenAfterReload(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()
	nodeA := NewDBRouteRegistry(database, dialect)
	nodeB := NewDBRouteRegistry(database, dialect)

	rt := &gateonv1.Route{Id: "r-peer", Name: "peer", Type: "http", Rule: "PathPrefix(`/peer`)", ServiceId: "svc"}
	if err := nodeA.Update(ctx, rt); err != nil {
		t.Fatal(err)
	}
	if _, ok := nodeB.Get(ctx, rt.Id); ok {
		t.Fatal("node B saw the route before any reload; the premise of the test is gone")
	}
	if err := nodeB.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if got, ok := nodeB.Get(ctx, rt.Id); !ok || got.Rule != rt.Rule {
		t.Fatalf("after a reload node B has %+v, %v; want the route node A wrote", got, ok)
	}
	if len(nodeB.GetByHost("")) == 0 && len(nodeB.List(ctx)) == 0 {
		t.Fatal("the reloaded route is not in the sorted list the router reads")
	}

	if err := nodeA.Delete(ctx, rt.Id); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := nodeB.Get(ctx, rt.Id); ok {
		t.Fatal("node B still serves a route node A deleted")
	}
}

// The same for the other registries a peer can change.
func TestAPeersConfigChangeIsSeenAfterReload(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()

	svcA, svcB := NewDBServiceRegistry(database, dialect), NewDBServiceRegistry(database, dialect)
	if err := svcA.Update(ctx, &gateonv1.Service{Id: "s1", Name: "one", BackendType: "http"}); err != nil {
		t.Fatal(err)
	}
	if err := svcB.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := svcB.Get(ctx, "s1"); !ok {
		t.Fatal("service written by a peer missing after reload")
	}

	mwA, mwB := NewDBMiddlewareRegistry(database, dialect), NewDBMiddlewareRegistry(database, dialect)
	if err := mwA.Update(ctx, &gateonv1.Middleware{Id: "m1", Name: "one", Type: "headers"}); err != nil {
		t.Fatal(err)
	}
	if err := mwB.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := mwB.Get(ctx, "m1"); !ok {
		t.Fatal("middleware written by a peer missing after reload")
	}

	epA, epB := NewDBEntryPointRegistry(database, dialect), NewDBEntryPointRegistry(database, dialect)
	if err := epA.Update(ctx, &gateonv1.EntryPoint{Id: "e1", Name: "web", Address: ":80"}); err != nil {
		t.Fatal(err)
	}
	if err := epB.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := epB.Get(ctx, "e1"); !ok {
		t.Fatal("entrypoint written by a peer missing after reload")
	}
	if err := epA.Delete(ctx, "e1"); err != nil {
		t.Fatal(err)
	}
	if err := epB.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := epB.Get(ctx, "e1"); ok {
		t.Fatal("entrypoint deleted by a peer still present after reload")
	}

	tlsA, tlsB := NewDBTLSOptionRegistry(database, dialect), NewDBTLSOptionRegistry(database, dialect)
	if err := tlsA.Update(ctx, &gateonv1.TLSOption{Id: "t1", Name: "modern"}); err != nil {
		t.Fatal(err)
	}
	if err := tlsB.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := tlsB.Get(ctx, "t1"); !ok {
		t.Fatal("TLS option written by a peer missing after reload")
	}
}

// A reload whose read fails leaves the registry serving what it had rather
// than nothing.
func TestAFailedReloadKeepsWhatTheRegistryHad(t *testing.T) {
	database, dialect := newTestDB(t)
	ctx := context.Background()
	reg := NewDBRouteRegistry(database, dialect)
	if err := reg.Update(ctx, &gateonv1.Route{Id: "r1", Name: "one", Type: "http", Rule: "Path(`/`)", ServiceId: "svc"}); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()
	if err := reg.Reload(ctx); err == nil {
		t.Fatal("a reload on a closed database reported success")
	}
	if _, ok := reg.Get(ctx, "r1"); !ok {
		t.Fatal("a failed reload emptied the registry")
	}
}
