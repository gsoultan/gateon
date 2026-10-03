// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// switchableBackend is a backend a test can stop and start again on the same
// address, the way a backend process dies and is restarted.
type switchableBackend struct {
	t    *testing.T
	name string
	addr string
	srv  *httptest.Server
}

func newSwitchableBackend(t *testing.T, name string) *switchableBackend {
	t.Helper()
	b := &switchableBackend{t: t, name: name}
	b.start("127.0.0.1:0")
	b.addr = b.srv.Listener.Addr().String()
	t.Cleanup(func() { b.srv.Close() })
	return b
}

func (b *switchableBackend) start(addr string) {
	b.t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		b.t.Fatalf("listen %s: %v", addr, err)
	}
	b.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Backend", b.name)
	}))
	_ = b.srv.Listener.Close()
	b.srv.Listener = ln
	b.srv.Start()
}

func (b *switchableBackend) stop()       { b.srv.Close() }
func (b *switchableBackend) restart()    { b.start(b.addr) }
func (b *switchableBackend) url() string { return "http://" + b.addr }

func statsFor(t *testing.T, ph *ProxyHandler, url string) TargetStats {
	t.Helper()
	for _, s := range ph.GetStats() {
		if s.URL == url {
			return s
		}
	}
	t.Fatalf("no stats for %s", url)
	return TargetStats{}
}

// TestTheDefaultHealthCheckEjectsADeadBackend: a service saved from the
// dashboard's defaults -- health check "Auto", no path -- ran no health check
// at all. A dead backend stayed in rotation for good (1 in N requests 502) and
// the dashboard showed it alive and CLOSED. With no path the check now
// connects to each target, with the same failure and recovery thresholds as
// any other check.
//
// One backend down: out of rotation after two failed checks, every request
// served by the other. Back up: in rotation after two good checks.
func TestTheDefaultHealthCheckEjectsADeadBackend(t *testing.T) {
	steady := namedBackends(t, "steady")["steady"]
	flaky := newSwitchableBackend(t, "flaky")
	ph := proxyFor(t, &gateonv1.Service{Id: "dflt", WeightedTargets: []*gateonv1.Target{
		{Url: steady, Weight: 1}, {Url: flaky.url(), Weight: 1},
	}})
	if !ph.healthChecked {
		t.Fatal("a service with the default health check (Auto, no path) runs no health check: " +
			"a dead backend would stay in rotation and read as healthy")
	}
	ctx, client := t.Context(), ph.healthHTTPClient()
	ph.checkAll(ctx, client)

	flaky.stop()
	ph.checkAll(ctx, client)
	if s := statsFor(t, ph, flaky.url()); !s.Alive {
		t.Fatal("one failed check took the target out; the unhealthy threshold is 2")
	}
	ph.checkAll(ctx, client)
	if s := statsFor(t, ph, flaky.url()); s.Alive || s.CircuitState != CircuitOpen {
		t.Fatalf("after two failed checks the dead backend reads alive=%v circuit=%s, want false/OPEN",
			s.Alive, s.CircuitState)
	}
	for _, name := range sequence(t, ph, 10) {
		if name != "steady" {
			t.Fatalf("a request reached %q after it was taken out of rotation", name)
		}
	}

	flaky.restart()
	ph.checkAll(ctx, client)
	if statsFor(t, ph, flaky.url()).Alive {
		t.Fatal("one good check brought the target back; the healthy threshold is 2")
	}
	ph.checkAll(ctx, client)
	if s := statsFor(t, ph, flaky.url()); !s.Alive || s.CircuitState != CircuitClosed {
		t.Fatalf("after two good checks the restarted backend reads alive=%v circuit=%s, want true/CLOSED",
			s.Alive, s.CircuitState)
	}
}

// TestEveryTargetDownAnswers503: with every target out of rotation the route
// answered 502, which says a backend answered badly. None was asked; the
// service is unavailable.
func TestEveryTargetDownAnswers503(t *testing.T) {
	only := newSwitchableBackend(t, "only")
	ph := proxyFor(t, &gateonv1.Service{Id: "alldown", WeightedTargets: []*gateonv1.Target{{Url: only.url(), Weight: 1}}})
	only.stop()
	ph.checkAll(t.Context(), ph.healthHTTPClient())
	rec := httptest.NewRecorder()
	ph.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://gw.test/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("every target down: status %d, want 503", rec.Code)
	}
}

// TestAnEmptyPathChecksByConnecting: with no path there is nothing to request,
// so the check is a TCP connection -- a target that accepts one is up, even if
// it speaks no HTTP. A path, when given, is requested.
func TestAnEmptyPathChecksByConnecting(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close() // accepts, says nothing
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done })
	target := "http://" + ln.Addr().String()

	for _, tc := range []struct {
		typ  gateonv1.HealthCheckType
		path string
		want bool
	}{
		{gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_UNSPECIFIED, "", true},
		{gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP, "", true}, // stored before save refused it
		{gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_CUSTOM, "", true},
		{gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_UNSPECIFIED, "/healthz", false},
	} {
		ph := proxyFor(t, &gateonv1.Service{Id: "conn", HealthCheckType: tc.typ, HealthCheckPath: tc.path,
			WeightedTargets: []*gateonv1.Target{{Url: target, Weight: 1}}})
		if !ph.healthChecked {
			t.Errorf("type %v path %q: no health check runs", tc.typ, tc.path)
		}
		if got := ph.checkTargetHealth(t.Context(), ph.healthHTTPClient(), target); got != tc.want {
			t.Errorf("type %v path %q: a target that accepts connections but speaks no HTTP checks %v, want %v",
				tc.typ, tc.path, got, tc.want)
		}
	}
}
