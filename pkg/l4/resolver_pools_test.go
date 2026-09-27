// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// sshAndRDPResolver is a resolver over one entrypoint carrying an SSH route and
// an RDP route to different backends -- a bastion entrypoint.
func sshAndRDPResolver(tb testing.TB) (*Resolver, *gateonv1.EntryPoint) {
	tb.Helper()
	dir := tb.TempDir()
	routes := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	for _, proto := range []struct{ name, backend string }{{"ssh", "10.0.0.1:22"}, {"rdp", "10.0.0.2:3389"}} {
		svc := &gateonv1.Service{
			Id:              proto.name + "-svc",
			BackendType:     "tcp",
			WeightedTargets: []*gateonv1.Target{{Url: "tcp://" + proto.backend}},
		}
		if err := services.Update(context.Background(), svc); err != nil {
			tb.Fatalf("add service: %v", err)
		}
		rt := &gateonv1.Route{Id: proto.name, Type: proto.name, Entrypoints: []string{"bastion"}, ServiceId: svc.Id}
		if err := routes.Update(context.Background(), rt); err != nil {
			tb.Fatalf("add route: %v", err)
		}
	}
	return NewResolver(routes, services), &gateonv1.EntryPoint{Id: "bastion"}
}

// TestEachProtocolRouteKeepsItsPool: connections to a bastion entrypoint
// alternate between its SSH and RDP routes. The pool cache was keyed by
// entrypoint alone, so every alternation looked like a configuration change:
// the pool was rebuilt with every backend marked alive again, its connection
// counts at zero and a new health-check goroutine -- per connection. A backend
// the health checks had taken out of rotation came back with the next
// connection of the other protocol.
func TestEachProtocolRouteKeepsItsPool(t *testing.T) {
	r, ep := sshAndRDPResolver(t)

	ssh := r.ResolveTCP(ep, "ssh")
	rdp := r.ResolveTCP(ep, "rdp")
	if ssh == nil || rdp == nil || ssh == rdp {
		t.Fatalf("resolved ssh=%p rdp=%p, want two distinct pools", ssh, rdp)
	}
	for range 3 {
		if again := r.ResolveTCP(ep, "ssh"); again != ssh {
			t.Fatal("an RDP connection in between rebuilt the SSH route's pool")
		}
		if again := r.ResolveTCP(ep, "rdp"); again != rdp {
			t.Fatal("an SSH connection in between rebuilt the RDP route's pool")
		}
	}
}

// TestInvalidatingAnEntrypointDropsAllItsPools: a route or service change
// invalidates by entrypoint, and that has to reach every protocol's pool on
// it, or a changed backend keeps receiving traffic.
func TestInvalidatingAnEntrypointDropsAllItsPools(t *testing.T) {
	r, ep := sshAndRDPResolver(t)
	ssh, rdp := r.ResolveTCP(ep, "ssh"), r.ResolveTCP(ep, "rdp")

	r.InvalidateEntrypoint(ep.Id)
	if r.ResolveTCP(ep, "ssh") == ssh || r.ResolveTCP(ep, "rdp") == rdp {
		t.Fatal("a pool survived InvalidateEntrypoint")
	}

	ssh, rdp = r.ResolveTCP(ep, "ssh"), r.ResolveTCP(ep, "rdp")
	r.InvalidateForRoute(&gateonv1.Route{Id: "ssh", Entrypoints: []string{ep.Id}})
	if r.ResolveTCP(ep, "ssh") == ssh || r.ResolveTCP(ep, "rdp") == rdp {
		t.Fatal("a pool on the route's entrypoint survived InvalidateForRoute")
	}
}

// BenchmarkResolveTCPAlternatingProtocols is a bastion entrypoint's lookup:
// consecutive connections for different protocol routes.
func BenchmarkResolveTCPAlternatingProtocols(b *testing.B) {
	r, ep := sshAndRDPResolver(b)
	protocols := [2]string{"ssh", "rdp"}
	i := 0
	b.ReportAllocs()
	for b.Loop() {
		if r.ResolveTCP(ep, protocols[i&1]) == nil {
			b.Fatal("a route stopped resolving")
		}
		i++
	}
}
