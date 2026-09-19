// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package k8s

import (
	"context"
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// client-go's ResourceEventHandler contract: OnDelete receives either the final
// state of the object or a cache.DeletedFinalStateUnknown wrapping it. The
// second shape arrives whenever the watch was closed and the deletion was only
// noticed on the next relist — an API-server restart, a rolled connection, a
// watch timeout. The handlers asserted the typed object with no comma-ok, so
// that ordinary shape panicked, and a panic inside an informer callback is not
// contained: utilruntime.HandleCrash re-panics by default (ReallyCrash == true),
// so the gateway process dies.
//
// A tombstone must be unwrapped and the delete applied, because the alternative
// to crashing is not "ignore it" — the routes of a deleted Ingress would stay in
// the routing table forever, still forwarding to a backend that no longer exists.

func TestIngressDeleteTombstoneIsUnwrappedNotPanicked(t *testing.T) {
	c := testController(t)
	ctx := context.Background()

	ing := ingress("prod", "web", []networkingv1.IngressRule{
		httpRule("web.example.com", "/", "web-svc", 80),
	})
	c.syncIngress(ing)
	if got := len(c.routeStore.List(ctx)); got != 1 {
		t.Fatalf("setup: got %d routes, want 1", got)
	}

	// Exactly what the informer delivers after a missed delete.
	c.onIngressDelete(cache.DeletedFinalStateUnknown{
		Key: "prod/web",
		Obj: ing,
	})

	if got := len(c.routeStore.List(ctx)); got != 0 {
		t.Fatalf("got %d routes after a tombstoned delete, want 0: the Ingress is "+
			"gone but its routes still forward to a backend that no longer exists", got)
	}
}

func TestHTTPRouteDeleteTombstoneIsUnwrappedNotPanicked(t *testing.T) {
	c := testController(t)
	ctx := context.Background()

	hr := httpRoute("default", "web", []string{"web.example.com"}, "/", "web-svc")
	c.syncHTTPRoute(hr)
	if got := len(c.routeStore.List(ctx)); got != 1 {
		t.Fatalf("setup: got %d routes, want 1", got)
	}

	c.onHTTPRouteDelete(cache.DeletedFinalStateUnknown{
		Key: "default/web",
		Obj: hr,
	})

	if got := len(c.routeStore.List(ctx)); got != 0 {
		t.Fatalf("got %d routes after a tombstoned delete, want 0", got)
	}
}

// A tombstone whose payload is not the expected type, and a raw event carrying
// the wrong object, must both be skipped rather than crash the process. The
// informer is shared: an object of another type reaching this handler is a
// programming error somewhere else, and taking the gateway down is never the
// right way to report one.
func TestHandlersSkipUnexpectedObjectsInsteadOfPanicking(t *testing.T) {
	c := testController(t)

	cases := []struct {
		name string
		call func()
	}{
		{"ingress delete, tombstone wrapping the wrong type", func() {
			c.onIngressDelete(cache.DeletedFinalStateUnknown{Key: "x", Obj: &gatewayv1.HTTPRoute{}})
		}},
		{"ingress delete, tombstone wrapping nil", func() {
			c.onIngressDelete(cache.DeletedFinalStateUnknown{Key: "x", Obj: nil})
		}},
		{"ingress upsert, wrong type", func() {
			c.onIngressUpsert(&gatewayv1.HTTPRoute{})
		}},
		{"httproute delete, tombstone wrapping the wrong type", func() {
			c.onHTTPRouteDelete(cache.DeletedFinalStateUnknown{Key: "x", Obj: &networkingv1.Ingress{}})
		}},
		{"httproute upsert, wrong type", func() {
			c.onHTTPRouteUpsert(&networkingv1.Ingress{})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.call() // must not panic
		})
	}

	if got := len(c.routeStore.List(context.Background())); got != 0 {
		t.Fatalf("got %d routes, want 0: unrecognised objects must change nothing", got)
	}
}

// The ordinary (non-tombstoned) delete must keep working: unwrapping must not
// become a path that only handles the exceptional shape.
func TestIngressDeleteStillHandlesTheTypedObject(t *testing.T) {
	c := testController(t)
	ctx := context.Background()

	ing := ingress("prod", "web", []networkingv1.IngressRule{
		httpRule("web.example.com", "/", "web-svc", 80),
	})
	c.syncIngress(ing)

	c.onIngressDelete(ing)

	if got := len(c.routeStore.List(ctx)); got != 0 {
		t.Fatalf("got %d routes after an ordinary delete, want 0", got)
	}
}

// The upsert path is what Add and Update both funnel through, so a valid object
// arriving there must still produce a route.
func TestIngressUpsertStillSyncs(t *testing.T) {
	c := testController(t)

	c.onIngressUpsert(&networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "web"},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{
			httpRule("web.example.com", "/api", "web-svc", 8080),
		}},
	})

	routes := c.routeStore.List(context.Background())
	if len(routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(routes))
	}
	if !strings.Contains(routes[0].Rule, "Host(`web.example.com`)") {
		t.Fatalf("Rule = %q, want the hostname matcher", routes[0].Rule)
	}
}
