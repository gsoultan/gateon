// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package posture

import (
	"fmt"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func l4Route(id, typ string, mws ...string) *gateonv1.Route {
	return &gateonv1.Route{Id: id, Name: id, Type: typ, Middlewares: mws}
}

func kindsFor(r BlindSpotReport, route string) []BlindSpotKind {
	var out []BlindSpotKind
	for _, s := range r.Spots {
		if s.Route == route {
			out = append(out, s.Kind)
		}
	}
	return out
}

// TestBlindSpotsNameEveryRouteTheWAFDoesNotStop walks one route of each kind
// and requires exactly the findings that kind earns: no more, so an enforcing
// route is not accused, and no fewer, so a passthrough is not missed.
func TestBlindSpotsNameEveryRouteTheWAFDoesNotStop(t *testing.T) {
	mws := index(
		mw("waf-on", "waf", map[string]string{"audit_only": "false"}),
		mw("waf-audit", "waf", map[string]string{"audit_only": "true"}),
		mw("office", "ipfilter", nil),
	)
	disabled := httpRoute("paused")
	disabled.Disabled = true
	c := Config{
		Global:      &gateonv1.GlobalConfig{},
		Middlewares: mws,
		Routes: []*gateonv1.Route{
			httpRoute("guarded", "waf-on"),
			httpRoute("watched", "waf-audit"),
			httpRoute("bare"),
			disabled,
			l4Route("ssh-open", "tcp"),
			l4Route("ssh-office", "tcp", "office"),
			l4Route("dns", "udp"),
		},
	}
	r := BlindSpots(c)
	want := map[string][]BlindSpotKind{
		"guarded":    nil,
		"paused":     nil,
		"watched":    {BlindWAFDetectOnly},
		"bare":       {BlindWAFOff},
		"ssh-open":   {BlindL4OpenToAll, BlindL4Passthrough},
		"ssh-office": {BlindL4Passthrough},
		"dns":        {BlindL4Passthrough},
	}
	for route, kinds := range want {
		if got := kindsFor(r, route); fmt.Sprint(got) != fmt.Sprint(kinds) {
			t.Errorf("route %q: %v, want %v", route, got, kinds)
		}
	}
	last := r.Spots[len(r.Spots)-1]
	if last.Kind != BlindWebSocketMessages || last.Route != "" {
		t.Errorf("the gateway-wide WebSocket entry is missing or not last: %+v", last)
	}
}

// TestBlindSpotsFollowTheGlobalWAF: a route with no WAF of its own is judged
// by the gateway-wide one, so turning that on must clear it.
func TestBlindSpotsFollowTheGlobalWAF(t *testing.T) {
	c := Config{Global: &gateonv1.GlobalConfig{}, Routes: []*gateonv1.Route{httpRoute("bare")}}
	if got := kindsFor(BlindSpots(c), "bare"); len(got) != 1 || got[0] != BlindWAFOff {
		t.Fatalf("with no WAF anywhere: %v, want waf_off", got)
	}
	c.Global = &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true}}
	if got := kindsFor(BlindSpots(c), "bare"); len(got) != 0 {
		t.Fatalf("under an enforcing global WAF: %v, want none", got)
	}
}

func TestBlindSpotsAreBounded(t *testing.T) {
	routes := make([]*gateonv1.Route, 0, MaxBlindSpots+50)
	for i := range MaxBlindSpots + 50 {
		routes = append(routes, httpRoute(fmt.Sprintf("r%04d", i)))
	}
	r := BlindSpots(Config{Global: &gateonv1.GlobalConfig{}, Routes: routes})
	if len(r.Spots) != MaxBlindSpots || r.Omitted != 51 {
		t.Errorf("%d spots, %d omitted; want %d and 51", len(r.Spots), r.Omitted, MaxBlindSpots)
	}
	if last := r.Spots[len(r.Spots)-1]; last.Kind != BlindWebSocketMessages {
		t.Errorf("the gateway-wide entry was cut with the routes: %+v", last)
	}
}
