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

// BenchmarkResolveTCP is what a TCP entrypoint pays to find its backend pool,
// which it does once per accepted connection. The pool itself is cached; this
// measures the lookup in front of the cache.
func BenchmarkResolveTCP(b *testing.B) {
	dir := b.TempDir()
	routes := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	svc := &gateonv1.Service{
		Id:              "svc",
		BackendType:     "tcp",
		WeightedTargets: []*gateonv1.Target{{Url: "tcp://10.0.0.1:5432"}, {Url: "tcp://10.0.0.2:5432"}},
	}
	if err := services.Update(context.Background(), svc); err != nil {
		b.Fatalf("add service: %v", err)
	}
	rt := &gateonv1.Route{Id: "rt", Type: "tcp", Entrypoints: []string{"ep"}, ServiceId: svc.Id}
	if err := routes.Update(context.Background(), rt); err != nil {
		b.Fatalf("add route: %v", err)
	}
	r := NewResolver(routes, services)
	ep := &gateonv1.EntryPoint{Id: "ep"}
	if r.ResolveTCP(ep, "") == nil {
		b.Fatal("the route did not resolve")
	}

	b.ReportAllocs()
	for b.Loop() {
		if r.ResolveTCP(ep, "") == nil {
			b.Fatal("the route stopped resolving")
		}
	}
}
