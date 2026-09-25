// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// throughEntrypointAndRoute serves one request the way a proxied request is
// measured: the entrypoint's Metrics around the route's MetricsWithService.
func throughEntrypointAndRoute(t *testing.T, host string, extra ...Middleware) {
	t.Helper()
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	route := append([]Middleware{MetricsWithService("once-route", "svc")}, extra...)
	h := Chain(
		EntryPoint("web", "web", false),
		Metrics("gateon-web"),
	)(Chain(route...)(backend))
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
}

// TestARequestIsCountedOnceWhereTheRouteDoesNotMatter: a proxied request
// passes the entrypoint's metrics and then its route's, and everything that
// does not depend on the route label was recorded by both -- path and domain
// statistics, country and protocol counts, per-IP bandwidth, and the per-IP
// aggregator that anomaly detection reads, which therefore saw every client at
// twice its real rate.
func TestARequestIsCountedOnceWhereTheRouteDoesNotMatter(t *testing.T) {
	const host = "metrics-once.example"
	domain := telemetry.RequestsByDomainTotal.WithLabelValues(telemetry.DomainLabel(host))
	protocol := telemetry.RequestsByProtocolTotal.WithLabelValues("http1")
	d0, p0 := counterValue(t, domain), counterValue(t, protocol)

	throughEntrypointAndRoute(t, host)

	if got := counterValue(t, domain) - d0; got != 1 {
		t.Errorf("one request counted %v times against its domain", got)
	}
	if got := counterValue(t, protocol) - p0; got != 1 {
		t.Errorf("one request counted %v times against its protocol", got)
	}
}

// TestEachLabelStillCountsTheRequest: the entrypoint's series and the route's
// are separate views -- the golden signals read the first, the route pages
// the second -- and both keep counting.
func TestEachLabelStillCountsTheRequest(t *testing.T) {
	ep := telemetry.RequestsTotal.WithLabelValues("gateon-web", "", "GET", "200")
	rt := telemetry.RequestsTotal.WithLabelValues("once-route", "svc", "GET", "200")
	e0, r0 := counterValue(t, ep), counterValue(t, rt)
	throughEntrypointAndRoute(t, "labels.example")
	if counterValue(t, ep)-e0 != 1 || counterValue(t, rt)-r0 != 1 {
		t.Fatalf("entrypoint +%v, route +%v; want each +1",
			counterValue(t, ep)-e0, counterValue(t, rt)-r0)
	}
}

type passedTo struct{ http.Handler }

// TestAttachedMetricsAndAccessLogDoNotDuplicateTheRoutes: every route already
// runs Metrics and AccessLog under its own name. A "metrics" or "accesslog"
// middleware attached without a name of its own measured the same route
// again -- a second request count (under an empty service label) and a
// second log line for each request.
func TestAttachedMetricsAndAccessLogDoNotDuplicateTheRoutes(t *testing.T) {
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	for _, typ := range []string{"metrics", "accesslog"} {
		mw, err := f.Create(&gateonv1.Middleware{Type: typ}, "once-route")
		if err != nil {
			t.Fatal(err)
		}
		inner := &passedTo{http.NotFoundHandler()}
		if got, ok := mw(inner).(*passedTo); !ok || got != inner {
			t.Errorf("an unnamed %s middleware wrapped the route instead of passing it through", typ)
		}
	}

	dup := telemetry.RequestsTotal.WithLabelValues("once-route", "", "GET", "200")
	before := counterValue(t, dup)
	mw, _ := f.Create(&gateonv1.Middleware{Type: "metrics"}, "once-route")
	throughEntrypointAndRoute(t, "attached.example", mw)
	if got := counterValue(t, dup) - before; got != 0 {
		t.Errorf("an unnamed metrics middleware counted the route's request again (%v)", got)
	}

	// A name of its own is a separate view, and still records.
	named := telemetry.RequestsTotal.WithLabelValues("checkout-view", "", "GET", "200")
	before = counterValue(t, named)
	mw, _ = f.Create(&gateonv1.Middleware{Type: "metrics", Config: map[string]string{"route": "checkout-view"}}, "once-route")
	throughEntrypointAndRoute(t, "named.example", mw)
	if got := counterValue(t, named) - before; got != 1 {
		t.Errorf("a metrics middleware with its own name counted %v requests, want 1", got)
	}
}
