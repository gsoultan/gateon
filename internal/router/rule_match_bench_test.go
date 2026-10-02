// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"net/http"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// BenchmarkSelectRouteFromSlice is the per-request cost of deciding a route
// from a sorted candidate list: the matcher for every rule ahead of the one
// that matches. The shapes are the ones the dashboard writes.
func BenchmarkSelectRouteFromSlice(b *testing.B) {
	routes := []*gateonv1.Route{
		{Id: "a", Rule: "Host(`api.example.com`) && PathPrefix(`/v2`) && Methods(`POST`, `PUT`)"},
		{Id: "b", Rule: "Host(`api.example.com`) && Headers(`X-Tier`, `gold`)"},
		{Id: "c", Rule: "Path(`/health`) || Path(`/ready`)"},
		{Id: "d", Rule: "Host(`api.example.com`) && PathPrefix(`/v1`)"},
	}
	req, err := http.NewRequest(http.MethodGet, "http://api.example.com/v1/users", nil)
	if err != nil {
		b.Fatal(err)
	}
	if got := SelectRouteFromSlice(req, routes); got == nil || got.Id != "d" {
		b.Fatalf("selected %v, want route d", got)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		SelectRouteFromSlice(req, routes)
	}
}
