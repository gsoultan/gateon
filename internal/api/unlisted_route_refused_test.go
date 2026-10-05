// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestARequestRefusedBeforeRoutingIsNotAnUnlistedRoute is T25. A client that
// tripped a honeypot is shunned at the entrypoint, so its later requests to
// routes that exist are refused before routing and traced under the
// entrypoint's label -- the label an unrouted request gets. Each produced a
// "Request to unlisted route/host" finding, and "Apply automatic fix" offered
// to create routes that already existed.
//
// The traces are as the Metrics middleware writes them: status as its decimal
// string, and the refusal mark the refusing middleware set.
func TestARequestRefusedBeforeRoutingIsNotAnUnlistedRoute(t *testing.T) {
	ep := "gateon-web"
	got := (&UnlistedRouteDetector{}).Detect(t.Context(), &DiagnosticData{Traces: []*telemetry.TraceRecord{
		{ServiceName: ep, Path: "/h/ok", Status: "403", Refusal: "mitigation", SourceIP: "10.0.0.66"},
		{ServiceDelay: 1, ServiceName: ep, Path: "/n/ok", Status: "403", SourceIP: "10.0.0.67"}, // an entrypoint filter, unmarked
		{ServiceDelay: 1, ServiceName: ep, Path: "/missing", Status: "404", SourceIP: "10.0.0.68"},
		{ServiceName: ep, Path: "/.env", Status: "403", Refusal: "mitigation", SourceIP: "10.0.0.66"},
	}})
	types := map[string]string{}
	for _, a := range got {
		types[a.GetRequestUri()] = a.GetType()
	}
	want := map[string]string{"/missing": "unlisted_route", "/.env": "honeypot_triggered"}
	if len(types) != len(want) {
		t.Fatalf("findings %v, want %v: a refused request is no evidence a route is missing", types, want)
	}
	for path, typ := range want {
		if types[path] != typ {
			t.Errorf("%s: finding %q, want %q", path, types[path], typ)
		}
	}
}
