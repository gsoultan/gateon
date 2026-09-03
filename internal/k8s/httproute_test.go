// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package k8s

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// The Ingress path was audited and two defects fixed there: rule metacharacters
// escaping the quoting, and a delete that matched on a prefix. Neither fix was
// applied to the Gateway API path, which is reachable by anyone who can create
// an HTTPRoute and had no tests at all.

func httpRoute(ns, name string, hostnames []string, path string, svc string) *gatewayv1.HTTPRoute {
	hs := make([]gatewayv1.Hostname, 0, len(hostnames))
	for _, h := range hostnames {
		hs = append(hs, gatewayv1.Hostname(h))
	}
	p := path
	port := gatewayv1.PortNumber(80)
	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: gatewayv1.HTTPRouteSpec{
			Hostnames: hs,
			Rules: []gatewayv1.HTTPRouteRule{{
				Matches: []gatewayv1.HTTPRouteMatch{{
					Path: &gatewayv1.HTTPPathMatch{Value: &p},
				}},
				BackendRefs: []gatewayv1.HTTPBackendRef{{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{
							Name: gatewayv1.ObjectName(svc),
							Port: &port,
						},
					},
				}},
			}},
		},
	}
}

func TestHTTPRouteSyncsAValidRoute(t *testing.T) {
	c := testController(t)
	c.syncHTTPRoute(httpRoute("default", "web", []string{"example.com"}, "/api", "web-svc"))

	routes := c.routeStore.List(context.Background())
	if len(routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(routes))
	}
	if !strings.Contains(routes[0].Rule, "Host(`example.com`)") {
		t.Errorf("rule %q does not carry the hostname", routes[0].Rule)
	}
	if !strings.Contains(routes[0].Rule, "PathPrefix(`/api`)") {
		t.Errorf("rule %q does not carry the path", routes[0].Rule)
	}
}

// TestHTTPRouteRejectsBacktickInHostname is the one that matters. The rule is
// backtick-quoted, so a hostname containing a backtick closes the quote and the
// rest is parsed as rule syntax -- a *working* rule that captures traffic for a
// host the author does not own.
func TestHTTPRouteRejectsBacktickInHostname(t *testing.T) {
	c := testController(t)
	c.syncHTTPRoute(httpRoute("default", "evil",
		[]string{"a`) || Host(`bank.example.com"}, "/", "evil-svc"))

	for _, r := range c.routeStore.List(context.Background()) {
		if strings.Contains(r.Rule, "bank.example.com") {
			t.Fatalf("a hostname with a backtick produced a rule capturing another host: %q", r.Rule)
		}
	}
}

func TestHTTPRouteRejectsBacktickInPath(t *testing.T) {
	c := testController(t)
	c.syncHTTPRoute(httpRoute("default", "evil", []string{"example.com"},
		"/`) || PathPrefix(`/admin", "evil-svc"))

	for _, r := range c.routeStore.List(context.Background()) {
		if strings.Contains(r.Rule, "/admin") {
			t.Fatalf("a path with a backtick produced a rule matching another path: %q", r.Rule)
		}
	}
}

// A rejected hostname must not leave a rule matching on path alone, which is
// broader than what the HTTPRoute asked for.
func TestHTTPRouteDoesNotWidenWhenAHostnameIsRejected(t *testing.T) {
	c := testController(t)
	c.syncHTTPRoute(httpRoute("default", "evil", []string{"bad`host"}, "/", "evil-svc"))

	for _, r := range c.routeStore.List(context.Background()) {
		if !strings.Contains(r.Rule, "Host(") {
			t.Fatalf("rejecting the hostname left a host-less rule %q, which matches more than intended", r.Rule)
		}
	}
}

// TestDeletingOneHTTPRouteLeavesTheOther is the second inherited defect.
// Matching on "k8s-hr-<ns>-<name>" alone makes "web" a prefix of "web-staging",
// so removing one HTTPRoute tears down another's routing -- in the direction
// that drops traffic.
func TestDeletingOneHTTPRouteLeavesTheOther(t *testing.T) {
	c := testController(t)
	ctx := context.Background()

	c.syncHTTPRoute(httpRoute("default", "web", []string{"web.example.com"}, "/", "web-svc"))
	c.syncHTTPRoute(httpRoute("default", "web-staging", []string{"staging.example.com"}, "/", "staging-svc"))

	if got := len(c.routeStore.List(ctx)); got != 2 {
		t.Fatalf("setup: got %d routes, want 2", got)
	}

	c.deleteHTTPRoute(httpRoute("default", "web", []string{"web.example.com"}, "/", "web-svc"))

	remaining := c.routeStore.List(ctx)
	if len(remaining) != 1 {
		t.Fatalf("got %d routes after deleting one HTTPRoute, want 1", len(remaining))
	}
	if !strings.Contains(remaining[0].Rule, "staging.example.com") {
		t.Errorf(`deleting "web" removed "web-staging"'s route; remaining rule is %q`, remaining[0].Rule)
	}
}

func TestDeletingAnHTTPRouteRemovesItsOwnRoutes(t *testing.T) {
	c := testController(t)
	ctx := context.Background()

	hr := httpRoute("default", "web", []string{"web.example.com"}, "/", "web-svc")
	c.syncHTTPRoute(hr)
	if len(c.routeStore.List(ctx)) == 0 {
		t.Fatal("setup: no routes created")
	}

	c.deleteHTTPRoute(hr)
	if got := len(c.routeStore.List(ctx)); got != 0 {
		t.Fatalf("got %d routes after deleting their HTTPRoute, want 0", got)
	}
}

// A rule with no backends produces no route rather than one pointing nowhere.
func TestHTTPRouteWithNoBackendCreatesNothing(t *testing.T) {
	c := testController(t)
	hr := httpRoute("default", "web", []string{"example.com"}, "/", "svc")
	hr.Spec.Rules[0].BackendRefs = nil

	c.syncHTTPRoute(hr)

	if got := len(c.routeStore.List(context.Background())); got != 0 {
		t.Errorf("got %d routes for a backend-less rule, want 0", got)
	}
}
