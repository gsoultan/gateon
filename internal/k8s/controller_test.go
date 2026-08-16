// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package k8s

import (
	"context"
	"strings"
	"testing"

	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gsoultan/gateon/internal/config"
)

// internal/k8s had no tests. It turns objects any cluster user with Ingress
// permission can create into this gateway's routing table, so its input is not
// trusted the way a config file is.

func testController(t *testing.T) *Controller {
	t.Helper()
	// Registries backed by real files: Update persists, and an empty registry
	// has no path, so every write fails and syncIngress silently creates
	// nothing. t.TempDir keeps them out of the checkout.
	dir := t.TempDir()
	return &Controller{
		routeStore:   config.NewRouteRegistry(filepath.Join(dir, "routes.json")),
		serviceStore: config.NewServiceRegistry(filepath.Join(dir, "services.json")),
	}
}

func ingress(ns, name string, rules []networkingv1.IngressRule) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       networkingv1.IngressSpec{Rules: rules},
	}
}

func httpRule(host, path string, svcName string, port int32) networkingv1.IngressRule {
	return networkingv1.IngressRule{
		Host: host,
		IngressRuleValue: networkingv1.IngressRuleValue{
			HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{{
					Path: path,
					Backend: networkingv1.IngressBackend{
						Service: &networkingv1.IngressServiceBackend{
							Name: svcName,
							Port: networkingv1.ServiceBackendPort{Number: port},
						},
					},
				}},
			},
		},
	}
}

func TestSyncIngress_CreatesRouteAndService(t *testing.T) {
	c := testController(t)
	ctx := context.Background()

	c.syncIngress(ingress("prod", "web", []networkingv1.IngressRule{
		httpRule("example.com", "/api", "web-svc", 8080),
	}))

	routes := c.routeStore.List(ctx)
	if len(routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(routes))
	}
	if !strings.Contains(routes[0].Rule, "Host(`example.com`)") {
		t.Fatalf("Rule = %q, want a Host matcher", routes[0].Rule)
	}
	if !strings.Contains(routes[0].Rule, "PathPrefix(`/api`)") {
		t.Fatalf("Rule = %q, want a PathPrefix matcher", routes[0].Rule)
	}
	if len(c.serviceStore.List(ctx)) != 1 {
		t.Fatal("expected the backing service to be created")
	}
}

// networkingv1.IngressBackend carries either a Service or a Resource. Reading
// Backend.Service.Name unconditionally panics on the Resource form — and this
// runs inside an informer callback, so the panic is not contained: it takes the
// gateway down. Anyone able to create an Ingress can do it, which in most
// clusters is a much larger set of people than "gateway administrator".
func TestSyncIngress_ResourceBackendDoesNotPanic(t *testing.T) {
	c := testController(t)

	ing := ingress("prod", "weird", []networkingv1.IngressRule{{
		Host: "example.com",
		IngressRuleValue: networkingv1.IngressRuleValue{
			HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{{
					Path: "/",
					// No Service. A Resource backend is valid Kubernetes.
					Backend: networkingv1.IngressBackend{
						Resource: &corev1.TypedLocalObjectReference{Kind: "StorageBucket", Name: "static"},
					},
				}},
			},
		},
	}})

	c.syncIngress(ing) // must not panic

	if got := len(c.routeStore.List(context.Background())); got != 0 {
		t.Fatalf("got %d routes, want 0: a backend this gateway cannot proxy must be skipped", got)
	}
}

// Rules are built by string interpolation into a backtick-quoted matcher, so a
// backtick in a host or path escapes the quoting and rewrites the expression.
// An Ingress that captured Host(`bank.example.com`) would be traffic
// interception, not a formatting bug.
func TestSyncIngress_RejectsRuleMetacharacters(t *testing.T) {
	t.Run("backtick in host", func(t *testing.T) {
		c := testController(t)
		c.syncIngress(ingress("prod", "evil", []networkingv1.IngressRule{
			httpRule("a`) || Host(`victim.example.com", "/", "svc", 80),
		}))
		for _, r := range c.routeStore.List(context.Background()) {
			if strings.Contains(r.Rule, "victim.example.com") {
				t.Fatalf("Rule = %q: a host escaped its quoting", r.Rule)
			}
		}
	})

	t.Run("backtick in path", func(t *testing.T) {
		c := testController(t)
		c.syncIngress(ingress("prod", "evil2", []networkingv1.IngressRule{
			httpRule("example.com", "/x`) || Host(`victim.example.com", "svc", 80),
		}))
		for _, r := range c.routeStore.List(context.Background()) {
			if strings.Contains(r.Rule, "victim.example.com") {
				t.Fatalf("Rule = %q: a path escaped its quoting", r.Rule)
			}
		}
	})
}

func TestSyncIngress_ExactPathTypeUsesPathMatcher(t *testing.T) {
	c := testController(t)
	exact := networkingv1.PathTypeExact

	rule := httpRule("example.com", "/exact", "svc", 80)
	rule.HTTP.Paths[0].PathType = &exact
	c.syncIngress(ingress("prod", "web", []networkingv1.IngressRule{rule}))

	routes := c.routeStore.List(context.Background())
	if len(routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(routes))
	}
	if !strings.Contains(routes[0].Rule, "Path(`/exact`)") || strings.Contains(routes[0].Rule, "PathPrefix") {
		t.Fatalf("Rule = %q, want an exact Path matcher", routes[0].Rule)
	}
}

func TestSyncIngress_ACMEAnnotationEnablesTLS(t *testing.T) {
	c := testController(t)

	ing := ingress("prod", "web", []networkingv1.IngressRule{
		httpRule("example.com", "/", "svc", 80),
	})
	ing.Annotations = map[string]string{"kubernetes.io/tls-acme": "true"}
	c.syncIngress(ing)

	routes := c.routeStore.List(context.Background())
	if len(routes) != 1 || routes[0].Tls == nil || !routes[0].Tls.AcmeEnabled {
		t.Fatalf("expected ACME to be enabled, got %+v", routes[0].Tls)
	}
}

// Route IDs are "k8s-<ns>-<name>-r<i>-p<j>" and deletion matched on the
// "k8s-<ns>-<name>" prefix alone. "web" is a prefix of "web-staging", so
// deleting one Ingress removed another Ingress's routes — silently, and in the
// direction that drops traffic.
func TestDeleteIngress_DoesNotRemoveASimilarlyNamedIngress(t *testing.T) {
	c := testController(t)
	ctx := context.Background()

	c.syncIngress(ingress("prod", "web", []networkingv1.IngressRule{
		httpRule("web.example.com", "/", "web-svc", 80),
	}))
	c.syncIngress(ingress("prod", "web-staging", []networkingv1.IngressRule{
		httpRule("staging.example.com", "/", "staging-svc", 80),
	}))
	if got := len(c.routeStore.List(ctx)); got != 2 {
		t.Fatalf("setup: got %d routes, want 2", got)
	}

	c.deleteIngress(ingress("prod", "web", nil))

	remaining := c.routeStore.List(ctx)
	if len(remaining) != 1 {
		t.Fatalf("got %d routes after deleting \"web\", want 1 (web-staging must survive)", len(remaining))
	}
	if !strings.Contains(remaining[0].Id, "web-staging") {
		t.Fatalf("surviving route is %q, want the web-staging one", remaining[0].Id)
	}
}

func TestDeleteIngress_RemovesItsOwnRoutes(t *testing.T) {
	c := testController(t)
	ctx := context.Background()

	c.syncIngress(ingress("prod", "web", []networkingv1.IngressRule{
		httpRule("a.example.com", "/one", "svc", 80),
		httpRule("b.example.com", "/two", "svc", 80),
	}))
	if got := len(c.routeStore.List(ctx)); got != 2 {
		t.Fatalf("setup: got %d routes, want 2", got)
	}

	c.deleteIngress(ingress("prod", "web", nil))

	if got := len(c.routeStore.List(ctx)); got != 0 {
		t.Fatalf("got %d routes, want 0", got)
	}
}
