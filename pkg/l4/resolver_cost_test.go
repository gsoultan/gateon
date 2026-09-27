// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// oneRouteResolver is a resolver over one generic TCP route from entrypoint
// "ep" to two backends.
func oneRouteResolver(t *testing.T) (*Resolver, *gateonv1.EntryPoint) {
	t.Helper()
	dir := t.TempDir()
	routes := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	svc := &gateonv1.Service{
		Id:              "svc",
		BackendType:     "tcp",
		WeightedTargets: []*gateonv1.Target{{Url: "tcp://10.0.0.1:5432"}, {Url: "tcp://10.0.0.2:5432"}},
	}
	if err := services.Update(context.Background(), svc); err != nil {
		t.Fatalf("add service: %v", err)
	}
	rt := &gateonv1.Route{Id: "rt", Type: "tcp", Entrypoints: []string{"ep"}, ServiceId: svc.Id}
	if err := routes.Update(context.Background(), rt); err != nil {
		t.Fatalf("add route: %v", err)
	}
	return NewResolver(routes, services), &gateonv1.EntryPoint{Id: "ep"}
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	out := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		out <- string(b)
	}()
	fn()
	_ = w.Close()
	return <-out
}

// TestResolvingARouteWritesNothingPerConnection: the TCP entrypoint resolves
// its route once per accepted connection, and resolution printed the service's
// backends to stdout with fmt.Printf every time -- a write(2) and a log line
// per connection, in whatever collects the service's output, bypassing the
// logger's level entirely.
func TestResolvingARouteWritesNothingPerConnection(t *testing.T) {
	r, ep := oneRouteResolver(t)
	_ = r.ResolveTCP(ep, "") // the first call builds the pool

	printed := captureStdout(t, func() {
		for range 3 {
			if r.ResolveTCP(ep, "") == nil {
				t.Error("the route did not resolve")
			}
		}
	})
	if printed != "" {
		t.Fatalf("three connections' route resolutions printed to stdout:\n%s", printed)
	}
}

// TestConfigHashDoesNotAllocate: the hash that tells a cached pool from a
// stale one is computed on every accepted connection. hash/fnv's constructor
// and four fmt.Sprintf calls made it eight allocations each time.
func TestConfigHashDoesNotAllocate(t *testing.T) {
	c := cfg(nil) // backends already in order, as a service usually lists them
	if n := testing.AllocsPerRun(100, func() { _ = configHash(c) }); n != 0 {
		t.Fatalf("configHash allocated %.0f times per call; it runs once per connection", n)
	}
}

// TestConfigHashIsFNV1aOfTheTerminatedFields pins the hash to its definition,
// so rewriting how it is computed cannot quietly change what it covers: FNV-1a
// over each field NUL-terminated, the integers in decimal, the backends sorted.
func TestConfigHashIsFNV1aOfTheTerminatedFields(t *testing.T) {
	for _, c := range []*L4Config{
		cfg(nil),
		cfg(func(c *L4Config) { c.Backends = []string{"z:1", "a:1", "m:1"}; c.ProxyProtocol = true }),
		cfg(func(c *L4Config) { c.HealthCheckInterval = -1; c.UDPMaxSessions = 0; c.Backends = nil }),
	} {
		h := fnv.New64a()
		write := func(s string) { _, _ = h.Write(append([]byte(s), 0)) }
		write(c.LoadBalancer)
		for _, n := range []int{c.HealthCheckInterval, c.HealthCheckTimeout, c.UDPSessionTimeout, c.UDPMaxSessions} {
			write(fmt.Sprintf("%d", n))
		}
		write(map[bool]string{true: "proxy", false: "noproxy"}[c.ProxyProtocol])
		backends := append([]string(nil), c.Backends...)
		sort.Strings(backends)
		for _, b := range backends {
			write(b)
		}
		if got, want := configHash(c), h.Sum64(); got != want {
			t.Errorf("configHash(%+v) = %#x, want FNV-1a %#x", *c, got, want)
		}
	}
}
