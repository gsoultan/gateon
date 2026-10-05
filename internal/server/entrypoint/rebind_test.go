// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/server/readiness"
	"github.com/gsoultan/gateon/internal/syncutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/quic-go/quic-go/http3"
)

// OPS-N5. An entrypoint was bound once, at startup. If its port was held at
// that moment -- the previous process still draining, a deploy overlapping --
// it logged an error and /readyz answered 503 naming it until someone
// restarted the gateway, long after the port had come free. A listener that
// fails now keeps retrying with a bounded backoff, and readiness and
// gateon_entrypoint_up recover when it binds.

// rebindBound is how long a test waits for a freed port to be taken up. The
// retry schedule below tries every 20 ms or less, so it binds in well under it.
const rebindBound = 3 * time.Second

// heldPort is a port the test holds and can free.
type heldPort struct {
	addr    string
	release func()
}

func holdTCP(t *testing.T) heldPort {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return heldPort{addr: l.Addr().String(), release: func() { _ = l.Close() }}
}

func holdUDP(t *testing.T, addr string) heldPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return heldPort{addr: pc.LocalAddr().String(), release: func() { _ = pc.Close() }}
}

// runWithFastRebind runs ep with a retry schedule fit for a test, and returns
// the channel each rebound address is reported on.
func runWithFastRebind(t *testing.T, ep *gateonv1.EntryPoint, deps *Deps) <-chan string {
	t.Helper()
	rebound := make(chan string, 4)
	deps.rebind = rebindPolicy{first: 5 * time.Millisecond, max: 20 * time.Millisecond,
		bound: func(addr string) { rebound <- addr }}
	wg := &syncutil.WaitGroup{}
	runnerFor(ep.Type).Run(t.Context(), ep, deps, wg)
	t.Cleanup(func() {
		ctx, cancel := contextWithBound()
		defer cancel()
		deps.ShutdownRegistry.ShutdownAll(ctx)
		wg.Wait()
	})
	return rebound
}

func awaitRebind(t *testing.T, rebound <-chan string, id, addr string) {
	t.Helper()
	select {
	case <-rebound:
	case <-time.After(rebindBound):
		t.Fatalf("entrypoint %s: %s came free and was not bound again within %v; readiness still says %q",
			id, addr, rebindBound, readiness.NotReady())
	}
	if namesEntrypoint(id) {
		t.Fatalf("entrypoint %s bound again but readiness still names it: %q", id, readiness.NotReady())
	}
	if up := entrypointUpGauge(t, id); up != 1 {
		t.Fatalf("entrypoint %s bound again but gateon_entrypoint_up is %v", id, up)
	}
}

// entrypointUpGauge reads gateon_entrypoint_up for id from the default registry.
func entrypointUpGauge(t *testing.T, id string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != "gateon_entrypoint_up" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "entrypoint" && l.GetValue() == id {
					return m.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatalf("no gateon_entrypoint_up series for %s", id)
	return -1
}

func TestAnEntrypointThatCouldNotBindBindsOnceThePortIsFree(t *testing.T) {
	for _, tc := range []struct {
		id    string
		typ   gateonv1.EntryPoint_Type
		check func(t *testing.T, addr string)
	}{
		{"rebind-http", gateonv1.EntryPoint_HTTP, func(t *testing.T, addr string) {
			resp, err := http.Get("http://" + addr + "/")
			if err != nil {
				t.Fatalf("GET after rebinding: %v", err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}},
		{"rebind-tcp", gateonv1.EntryPoint_TCP, func(t *testing.T, addr string) {
			c, err := net.DialTimeout("tcp", addr, rebindBound)
			if err != nil {
				t.Fatalf("dial after rebinding: %v", err)
			}
			_ = c.Close()
		}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			held := holdTCP(t)
			deps := mockDepsForInspection(t)
			ep := &gateonv1.EntryPoint{Id: tc.id, Name: tc.id, Address: held.addr, Type: tc.typ}
			rebound := runWithFastRebind(t, ep, deps)
			if !namesEntrypoint(tc.id) {
				t.Fatalf("precondition: %s could not bind and readiness does not say so", tc.id)
			}
			if up := entrypointUpGauge(t, tc.id); up != 0 {
				t.Fatalf("precondition: gateon_entrypoint_up for %s is %v while it cannot bind", tc.id, up)
			}
			held.release()
			awaitRebind(t, rebound, tc.id, held.addr)
			tc.check(t, held.addr)
		})
	}
}

func TestAUDPEntrypointThatCouldNotBindBindsOnceThePortIsFree(t *testing.T) {
	held := holdUDP(t, "127.0.0.1:0")
	deps := mockDepsForInspection(t)
	ep := &gateonv1.EntryPoint{Id: "rebind-udp", Name: "rebind-udp", Address: held.addr, Type: gateonv1.EntryPoint_UDP}
	rebound := runWithFastRebind(t, ep, deps)
	if !namesEntrypoint("rebind-udp") {
		t.Fatal("precondition: the UDP entrypoint could not bind and readiness does not say so")
	}
	held.release()
	awaitRebind(t, rebound, "rebind-udp", held.addr)
}

// TestAnHTTP3ListenerThatCouldNotBindBindsOnceThePortIsFree: the QUIC half of
// an HTTP/3 entrypoint fails on its own (UDP held, TCP free), and is retried
// on its own; once bound it serves.
func TestAnHTTP3ListenerThatCouldNotBindBindsOnceThePortIsFree(t *testing.T) {
	addr := freeTCPAndUDPAddr(t)
	held := holdUDP(t, addr)
	serverTLS, clientTLS := selfSignedTLS(t)
	deps := mockDepsForInspection(t)
	deps.TLSConfig = serverTLS
	ep := &gateonv1.EntryPoint{Id: "rebind-h3", Name: "rebind-h3", Address: addr, Type: gateonv1.EntryPoint_HTTP3,
		Tls: &gateonv1.TlsConfig{Enabled: true}}
	rebound := runWithFastRebind(t, ep, deps)
	if !namesEntrypoint("rebind-h3") {
		t.Fatal("precondition: the QUIC listener could not bind and readiness does not say so")
	}
	held.release()
	awaitRebind(t, rebound, "rebind-h3", "udp "+addr)

	tr := &http3.Transport{TLSClientConfig: clientTLS.Clone()}
	t.Cleanup(func() { _ = tr.Close() })
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+addr+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatalf("HTTP/3 request after rebinding: %v", err)
	}
	_ = resp.Body.Close()
}
