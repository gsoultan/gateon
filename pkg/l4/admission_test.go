// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware/security"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// countingEcho is a backend that echoes and counts the connections it accepts,
// so a test can tell a refused connection from one that reached the backend.
type countingEcho struct {
	addr     string
	accepted atomic.Int32
}

func newCountingEcho(t *testing.T) *countingEcho {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	b := &countingEcho{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.accepted.Add(1)
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return b
}

// filteredSSH is a resolver with one SSH route to backend that lists mws, and
// the middleware registry they are stored in.
func filteredSSH(t *testing.T, backend string, mws ...*gateonv1.Middleware) (*Resolver, *config.MiddlewareRegistry, *gateonv1.EntryPoint) {
	t.Helper()
	dir := t.TempDir()
	ctx := context.Background()
	routes := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	store := config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json"))
	svc := &gateonv1.Service{Id: "ssh-svc", BackendType: "tcp", WeightedTargets: []*gateonv1.Target{{Url: "tcp://" + backend}}}
	if err := services.Update(ctx, svc); err != nil {
		t.Fatalf("add service: %v", err)
	}
	ids := make([]string, 0, len(mws))
	for _, mw := range mws {
		ids = append(ids, mw.Id)
		if mw.Type == "" { // a reference to a middleware that is not stored
			continue
		}
		if err := store.Update(ctx, mw); err != nil {
			t.Fatalf("add middleware: %v", err)
		}
	}
	rt := &gateonv1.Route{Id: "ssh", Name: "bastion-ssh", Type: "ssh", Entrypoints: []string{"bastion"}, ServiceId: svc.Id, Middlewares: ids}
	if err := routes.Update(ctx, rt); err != nil {
		t.Fatalf("add route: %v", err)
	}
	r := NewResolver(routes, services)
	r.SetAddrFilters(store, security.NewAddrFilter)
	return r, store, &gateonv1.EntryPoint{Id: "bastion"}
}

// reachesBackend opens a loopback connection, hands the accepted side to the
// route the resolver picks for SSH, and reports whether a message came back
// through the backend.
func reachesBackend(t *testing.T, r *Resolver, ep *gateonv1.EntryPoint) bool {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	p := r.ResolveTCP(ep, "ssh")
	if p == nil {
		t.Fatal("no proxy resolved for the ssh route")
	}
	go p.ProxyTCP(context.Background(), server)

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	msg := []byte("SSH-2.0-OpenSSH_10.6\r\n")
	if _, err := client.Write(msg); err != nil {
		return false
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(client, buf); err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("connection neither proxied nor closed: timed out")
		}
		return false
	}
	return string(buf) == string(msg)
}

func ipFilter(id, allow, deny string) *gateonv1.Middleware {
	return &gateonv1.Middleware{Id: id, Name: id, Type: "ipfilter", Config: map[string]string{"allow_list": allow, "deny_list": deny}}
}

// TestSSHRouteEnforcesItsIPFilter: an ipfilter attached to an SSH route was
// saved, shown on the route, and never read -- the L4 path consulted only the
// route's service, so the route accepted every address. The connection here
// comes from 127.0.0.1, outside the allow list, and must not reach the backend.
func TestSSHRouteEnforcesItsIPFilter(t *testing.T) {
	cases := []struct {
		name  string
		mws   []*gateonv1.Middleware
		admit bool
	}{
		{"allow list excludes the peer", []*gateonv1.Middleware{ipFilter("office", "10.0.0.0/8", "")}, false},
		{"deny list names the peer", []*gateonv1.Middleware{ipFilter("block", "", "127.0.0.0/8")}, false},
		{"allow list names the peer", []*gateonv1.Middleware{ipFilter("local", "127.0.0.1", "")}, true},
		{"every filter must admit", []*gateonv1.Middleware{ipFilter("local", "127.0.0.1", ""), ipFilter("office", "10.0.0.0/8", "")}, false},
		{"a missing middleware refuses", []*gateonv1.Middleware{{Id: "deleted"}}, false},
		{"an unreadable stored filter refuses", []*gateonv1.Middleware{ipFilter("typo", "10.0.0/8", "")}, false},
		{"a non-L4 middleware changes nothing", []*gateonv1.Middleware{{Id: "hdr", Name: "hdr", Type: "headers"}}, true},
		{"no middleware admits", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend := newCountingEcho(t)
			r, _, ep := filteredSSH(t, backend.addr, tc.mws...)
			if got := reachesBackend(t, r, ep); got != tc.admit {
				t.Fatalf("connection reached backend = %v, want %v", got, tc.admit)
			}
			if !tc.admit && backend.accepted.Load() != 0 {
				t.Fatalf("a refused connection was still dialled to the backend (%d accepts)", backend.accepted.Load())
			}
		})
	}
}

// TestSSHRouteFilterEditTakesEffect: the filter is cached per route, so an edit
// to the middleware must be seen by the next connection without a restart or
// an explicit invalidation -- in both directions.
func TestSSHRouteFilterEditTakesEffect(t *testing.T) {
	backend := newCountingEcho(t)
	r, store, ep := filteredSSH(t, backend.addr, ipFilter("office", "10.0.0.0/8", ""))
	if reachesBackend(t, r, ep) {
		t.Fatal("peer outside the allow list reached the backend")
	}
	if err := store.Update(context.Background(), ipFilter("office", "10.0.0.0/8,127.0.0.1", "")); err != nil {
		t.Fatalf("edit middleware: %v", err)
	}
	if !reachesBackend(t, r, ep) {
		t.Fatal("peer added to the allow list is still refused")
	}
	if err := store.Update(context.Background(), ipFilter("office", "10.0.0.0/8", "")); err != nil {
		t.Fatalf("edit middleware: %v", err)
	}
	if reachesBackend(t, r, ep) {
		t.Fatal("peer removed from the allow list still reaches the backend")
	}
}
