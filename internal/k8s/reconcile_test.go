// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package k8s

import (
	"context"
	"slices"
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
)

func rules(c *Controller) []string {
	var out []string
	for _, r := range c.routeStore.List(context.Background()) {
		out = append(out, r.Rule)
	}
	slices.Sort(out)
	return out
}

// TestRemovedIngressPathStopsRouting: sync only ever upserted, so a path
// deleted from an Ingress left its route behind, still sending that path's
// traffic to the old backend until the whole Ingress was deleted.
func TestRemovedIngressPathStopsRouting(t *testing.T) {
	c := testController(t)
	two := httpRule("example.com", "/api", "api", 80)
	two.HTTP.Paths = append(two.HTTP.Paths, httpRule("example.com", "/old", "old", 80).HTTP.Paths...)
	c.syncIngress(ingress("prod", "web", []networkingv1.IngressRule{two}))
	if n := len(rules(c)); n != 2 {
		t.Fatalf("synced %d routes for two paths", n)
	}
	c.syncIngress(ingress("prod", "web", []networkingv1.IngressRule{httpRule("example.com", "/api", "api", 80)}))
	if got := rules(c); len(got) != 1 || strings.Contains(got[0], "/old") {
		t.Fatalf("after removing /old the routes are %v", got)
	}
}

// TestRemovedHTTPRouteMatchStopsRouting is the same for the Gateway API.
func TestRemovedHTTPRouteMatchStopsRouting(t *testing.T) {
	c := testController(t)
	hr := httpRoute("default", "web", []string{"example.com"}, "/api", "web-svc")
	old := "/old"
	hr.Spec.Rules[0].Matches = append(hr.Spec.Rules[0].Matches, gatewayv1.HTTPRouteMatch{Path: &gatewayv1.HTTPPathMatch{Value: &old}})
	c.syncHTTPRoute(hr)
	if n := len(rules(c)); n != 2 {
		t.Fatalf("synced %d routes for two matches", n)
	}
	c.syncHTTPRoute(httpRoute("default", "web", []string{"example.com"}, "/api", "web-svc"))
	if got := rules(c); len(got) != 1 || strings.Contains(got[0], "/old") {
		t.Fatalf("after removing /old the routes are %v", got)
	}
}

// TestHTTPRouteWithSeveralHostnamesRoutesEach: the rule was written as
// Host(`a`, `b`), and the router reads one host per Host(): it took the
// literal "a`, `b" as the host, which no request carries, so an HTTPRoute
// with more than one hostname routed nothing.
func TestHTTPRouteWithSeveralHostnamesRoutesEach(t *testing.T) {
	c := testController(t)
	c.syncHTTPRoute(httpRoute("default", "web", []string{"a.example", "b.example"}, "/api", "web-svc"))
	got := rules(c)
	want := []string{"Host(`a.example`) && PathPrefix(`/api`)", "Host(`b.example`) && PathPrefix(`/api`)"}
	if !slices.Equal(got, want) {
		t.Fatalf("rules = %q, want %q", got, want)
	}
}

// TestHTTPRouteKeepsItsMethodAndHeaderMatches: a match on method or header
// was dropped, so a route meant only for, say, requests carrying a canary
// header took every request for its path.
func TestHTTPRouteKeepsItsMethodAndHeaderMatches(t *testing.T) {
	c := testController(t)
	hr := httpRoute("default", "canary", []string{"example.com"}, "/api", "canary-svc")
	get := gatewayv1.HTTPMethodGet
	hr.Spec.Rules[0].Matches[0].Method = &get
	hr.Spec.Rules[0].Matches[0].Headers = []gatewayv1.HTTPHeaderMatch{{Name: "X-Env", Value: "canary"}}
	c.syncHTTPRoute(hr)
	got := rules(c)
	if len(got) != 1 || !strings.Contains(got[0], "Methods(`GET`)") || !strings.Contains(got[0], "Headers(`X-Env`, `canary`)") {
		t.Fatalf("rules = %q, want the method and header kept", got)
	}
}

// TestHTTPRouteRefusesMatchesItCannotExpress: a regular-expression header or a
// query match has no equivalent in the rule language, and dropping it would
// widen the route, so the match is skipped instead.
func TestHTTPRouteRefusesMatchesItCannotExpress(t *testing.T) {
	c := testController(t)
	hr := httpRoute("default", "strict", []string{"example.com"}, "/api", "svc")
	re := gatewayv1.HeaderMatchRegularExpression
	hr.Spec.Rules[0].Matches[0].Headers = []gatewayv1.HTTPHeaderMatch{{Type: &re, Name: "X-Env", Value: "canary.*"}}
	c.syncHTTPRoute(hr)
	hr2 := httpRoute("default", "query", []string{"example.com"}, "/api", "svc")
	hr2.Spec.Rules[0].Matches[0].QueryParams = []gatewayv1.HTTPQueryParamMatch{{Name: "beta", Value: "1"}}
	c.syncHTTPRoute(hr2)
	if got := rules(c); len(got) != 0 {
		t.Fatalf("matches the rule language cannot express became routes: %q", got)
	}
}

// TestHTTPRouteRuleWithoutMatchesRoutesEverything: a rule with no matches
// means a prefix match on "/", by the Gateway API's definition. It produced no
// route at all.
func TestHTTPRouteRuleWithoutMatchesRoutesEverything(t *testing.T) {
	c := testController(t)
	hr := httpRoute("default", "all", []string{"example.com"}, "/", "svc")
	hr.Spec.Rules[0].Matches = nil
	c.syncHTTPRoute(hr)
	if got := rules(c); len(got) != 1 || got[0] != "Host(`example.com`) && PathPrefix(`/`)" {
		t.Fatalf("rules = %q, want one route for everything under example.com", got)
	}
}

// TestControllerWatchesOnlyItsNamespace: with the chart's watchNamespace the
// controller holds a Role for one namespace, and its informers listed every
// namespace anyway -- refused by that Role, so they never synced and nothing
// was routed. Scoped, they see only their own namespace's objects.
func TestControllerWatchesOnlyItsNamespace(t *testing.T) {
	client := k8sfake.NewClientset(
		ingress("team-a", "web", []networkingv1.IngressRule{httpRule("a.example", "/", "web", 80)}),
		ingress("team-b", "web", []networkingv1.IngressRule{httpRule("b.example", "/", "web", 80)}),
	)
	base := testController(t)
	c := NewController(t.Context(), client, gwfake.NewClientset(), base.routeStore, base.serviceStore, "team-a")
	stop := make(chan struct{})
	defer close(stop)
	c.factory.Start(stop)
	if !cache.WaitForCacheSync(stop, c.informer.HasSynced) {
		t.Fatal("ingress informer never synced")
	}
	objs := c.informer.GetStore().List()
	if len(objs) != 1 || objs[0].(*networkingv1.Ingress).Namespace != "team-a" {
		t.Fatalf("a controller scoped to team-a holds %d ingresses", len(objs))
	}
}

// A route's name is what its metrics, access logs and threat records are
// reported under. Every path of an Ingress rule, and every match and host of
// an HTTPRoute rule, was given the rule's name, so their numbers were summed
// under one name -- and, while per-route state was keyed by name, they shared
// a circuit breaker and cache entries too.
func TestGeneratedRoutesHaveNamesOfTheirOwn(t *testing.T) {
	c := testController(t)
	two := httpRule("example.com", "/api", "api", 80)
	two.HTTP.Paths = append(two.HTTP.Paths, httpRule("example.com", "/old", "old", 80).HTTP.Paths...)
	c.syncIngress(ingress("prod", "web", []networkingv1.IngressRule{two}))

	hr := httpRoute("default", "web", []string{"a.example", "b.example"}, "/api", "web-svc")
	other := "/other"
	hr.Spec.Rules[0].Matches = append(hr.Spec.Rules[0].Matches, gatewayv1.HTTPRouteMatch{Path: &gatewayv1.HTTPPathMatch{Value: &other}})
	c.syncHTTPRoute(hr)

	names := map[string]string{}
	for _, r := range c.routeStore.List(context.Background()) {
		if prev, dup := names[r.Name]; dup {
			t.Errorf("routes %s and %s are both named %q", prev, r.Id, r.Name)
		}
		names[r.Name] = r.Id
	}
	if len(names) != 6 {
		t.Fatalf("got %d distinctly named routes, want 6 (two Ingress paths, two matches on two hosts)", len(names))
	}
}
