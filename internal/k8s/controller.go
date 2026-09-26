// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package k8s

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"
)

// Controller watches Kubernetes Ingress and Gateway API resources and syncs them to Gateon.
type Controller struct {
	// ctx bounds the store writes the informer callbacks make; the callbacks
	// themselves carry none.
	ctx           context.Context
	client        kubernetes.Interface
	gatewayClient gatewayclient.Interface
	routeStore    config.RouteStore
	serviceStore  config.ServiceStore
	informer      cache.SharedIndexInformer
	factory       informers.SharedInformerFactory
	gwInformer    cache.SharedIndexInformer
	gwFactory     gatewayinformers.SharedInformerFactory
}

// NewController creates a new Kubernetes Ingress and Gateway API Controller.
// NewController watches Ingresses and HTTPRoutes in namespace, or in every
// namespace when it is empty.
//
// The chart's watchNamespace grants a namespaced Role instead of a ClusterRole,
// and the informers used to list cluster-wide regardless -- which that Role
// forbids, so they never synced and a namespace-scoped install routed nothing
// from Kubernetes at all. The namespace now reaches the informers through
// GATEON_K8S_WATCH_NAMESPACE, which the chart sets from the same value.
func NewController(ctx context.Context, client kubernetes.Interface, gatewayClient gatewayclient.Interface, routeStore config.RouteStore, serviceStore config.ServiceStore, namespace string) *Controller {
	factory := informers.NewSharedInformerFactoryWithOptions(client, 30*time.Second, informers.WithNamespace(namespace))
	informer := factory.Networking().V1().Ingresses().Informer()

	gwFactory := gatewayinformers.NewSharedInformerFactoryWithOptions(gatewayClient, 30*time.Second, gatewayinformers.WithNamespace(namespace))
	gwInformer := gwFactory.Gateway().V1().HTTPRoutes().Informer()

	c := &Controller{
		ctx:           ctx,
		client:        client,
		gatewayClient: gatewayClient,
		routeStore:    routeStore,
		serviceStore:  serviceStore,
		informer:      informer,
		factory:       factory,
		gwInformer:    gwInformer,
		gwFactory:     gwFactory,
	}

	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) { c.onIngressUpsert(obj) },
		UpdateFunc: func(_, newObj any) {
			c.onIngressUpsert(newObj)
		},
		DeleteFunc: c.onIngressDelete,
	})

	_, _ = gwInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) { c.onHTTPRouteUpsert(obj) },
		UpdateFunc: func(_, newObj any) {
			c.onHTTPRouteUpsert(newObj)
		},
		DeleteFunc: c.onHTTPRouteDelete,
	})

	return c
}

// unwrapTombstone returns the object a delete notification is really about.
//
// client-go's ResourceEventHandler contract says OnDelete receives either the
// final state of the object or a cache.DeletedFinalStateUnknown wrapping it,
// the latter whenever the watch was closed and the deletion was only noticed on
// the next relist — an ordinary consequence of an API-server restart, a rolled
// connection or a watch timeout, not an exotic condition. Asserting the typed
// object directly panicked on that shape, and the panic happens inside the
// informer's own goroutine, where utilruntime.HandleCrash re-panics by default
// (ReallyCrash is true), so it takes the gateway process down rather than being
// contained.
func unwrapTombstone(obj any) any {
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		return tombstone.Obj
	}
	return obj
}

// onIngressUpsert handles an add or update. The assertion is comma-ok because a
// handler that cannot recognise its object must skip it, not crash the process:
// an informer callback panic is not contained.
func (c *Controller) onIngressUpsert(obj any) {
	ing, ok := obj.(*networkingv1.Ingress)
	if !ok {
		logger.L.LogWarn("ignoring ingress event carrying an unexpected object",
			"type", fmt.Sprintf("%T", obj))
		return
	}
	c.syncIngress(ing)
}

func (c *Controller) onIngressDelete(obj any) {
	ing, ok := unwrapTombstone(obj).(*networkingv1.Ingress)
	if !ok {
		logger.L.LogWarn("ignoring ingress delete carrying an unexpected object",
			"type", fmt.Sprintf("%T", obj))
		return
	}
	c.deleteIngress(ing)
}

func (c *Controller) onHTTPRouteUpsert(obj any) {
	hr, ok := obj.(*gatewayv1.HTTPRoute)
	if !ok {
		logger.L.LogWarn("ignoring httproute event carrying an unexpected object",
			"type", fmt.Sprintf("%T", obj))
		return
	}
	c.syncHTTPRoute(hr)
}

func (c *Controller) onHTTPRouteDelete(obj any) {
	hr, ok := unwrapTombstone(obj).(*gatewayv1.HTTPRoute)
	if !ok {
		logger.L.LogWarn("ignoring httproute delete carrying an unexpected object",
			"type", fmt.Sprintf("%T", obj))
		return
	}
	c.deleteHTTPRoute(hr)
}

// Run starts the controller sync loop.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer runtime.HandleCrash()
	go c.factory.Start(stopCh)
	go c.gwFactory.Start(stopCh)

	if !cache.WaitForCacheSync(stopCh, c.informer.HasSynced, c.gwInformer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}
	<-stopCh
}

// safeForRule reports whether s can be interpolated into a route matcher.
//
// Rules are assembled as Host(`x`) && PathPrefix(`y`), so a backtick in x or y
// closes the literal early and the rest of the value becomes expression. An
// Ingress carrying "a`) || Host(`bank.example.com" would not be a malformed
// rule, it would be a working one that captures somebody else's traffic — and
// Ingress objects come from whoever holds that permission in the cluster, which
// is rarely only the gateway's administrator.
//
// Backslash and newline are refused for the same reason: neither appears in a
// DNS name or a URL path, so nothing legitimate is lost by declining them.
func safeForRule(s string) bool {
	return !strings.ContainsAny(s, "`\\\n\r")
}

func (c *Controller) syncIngress(ing *networkingv1.Ingress) {
	ctx := c.ctx
	ingressID := fmt.Sprintf("k8s-%s-%s", ing.Namespace, ing.Name)
	keep := make(map[string]bool)
	defer func() { c.removeRoutesExcept(ctx, ingressID+"-r", keep) }()

	for i, rule := range ing.Spec.Rules {
		host := rule.Host
		if rule.HTTP == nil {
			continue
		}
		if !safeForRule(host) {
			logger.L.LogError("skipping ingress rule: host contains a character that would escape the route expression",
				"namespace", ing.Namespace, "ingress", ing.Name, "host", host)
			continue
		}

		for j, path := range rule.HTTP.Paths {
			// An IngressBackend carries either a Service or a Resource, and the
			// Resource form is valid Kubernetes that this gateway cannot proxy.
			// Reading Service.Name without checking dereferenced nil and panicked
			// inside the informer callback, so any cluster user able to create an
			// Ingress could stop the gateway.
			if path.Backend.Service == nil {
				logger.L.LogWarn("skipping ingress path: backend is not a Service",
					"namespace", ing.Namespace, "ingress", ing.Name, "path", path.Path)
				continue
			}
			if !safeForRule(path.Path) {
				logger.L.LogError("skipping ingress path: path contains a character that would escape the route expression",
					"namespace", ing.Namespace, "ingress", ing.Name, "path", path.Path)
				continue
			}

			routeID := fmt.Sprintf("%s-r%d-p%d", ingressID, i, j)
			// Kept even if a store write below fails: a transient failure must
			// not delete the route the Ingress still asks for.
			keep[routeID] = true
			serviceID := fmt.Sprintf("%s-svc-%s-%d", ingressID, path.Backend.Service.Name, path.Backend.Service.Port.Number)

			// 1. Create/Update Gateon Service
			svc := &gateonv1.Service{
				Id:           serviceID,
				Name:         fmt.Sprintf("k8s/%s/%s", ing.Namespace, path.Backend.Service.Name),
				DiscoveryUrl: fmt.Sprintf("dns:%s.%s.svc.cluster.local", path.Backend.Service.Name, ing.Namespace),
				BackendType:  "http",
			}
			if err := c.serviceStore.Update(ctx, svc); err != nil {
				logger.L.LogError("failed to sync k8s service", "error", err, "service_id", serviceID)
				continue
			}

			// 2. Create/Update Gateon Route
			pathStr := path.Path
			if pathStr == "" {
				pathStr = "/"
			}
			ruleStr := fmt.Sprintf("Host(`%s`)", host)
			if pathStr != "/" {
				if path.PathType != nil && *path.PathType == networkingv1.PathTypeExact {
					ruleStr += fmt.Sprintf(" && Path(`%s`)", pathStr)
				} else {
					ruleStr += fmt.Sprintf(" && PathPrefix(`%s`)", pathStr)
				}
			}

			route := &gateonv1.Route{
				Id:        routeID,
				Name:      fmt.Sprintf("k8s/%s/%s/%d/%d", ing.Namespace, ing.Name, i, j),
				Rule:      ruleStr,
				Type:      "http",
				ServiceId: serviceID,
			}

			// Check for ACME annotation
			if ing.Annotations["kubernetes.io/tls-acme"] == "true" {
				route.Tls = &gateonv1.RouteTLSConfig{
					AcmeEnabled: true,
				}
			}

			if err := c.routeStore.Update(ctx, route); err != nil {
				logger.L.LogError("failed to sync k8s route", "error", err, "route", route.Name)
			}
		}
	}
}

func (c *Controller) deleteIngress(ing *networkingv1.Ingress) {
	// The "-r" is what keeps this from deleting a different Ingress's routes.
	// Route IDs are "<ingressID>-r<i>-p<j>", and matching on ingressID alone
	// made "web" a prefix of "web-staging", so removing one Ingress silently
	// tore down another's routing — in the direction that drops traffic.
	//
	// Note this does not resolve the underlying ambiguity: namespace "prod-web"
	// with name "staging" and namespace "prod" with name "web-staging" both
	// produce "k8s-prod-web-staging". Separating those needs a different ID
	// format, which would orphan the routes of every already-running deployment,
	// so it is left alone here.
	c.removeRoutesExcept(c.ctx, fmt.Sprintf("k8s-%s-%s-r", ing.Namespace, ing.Name), nil)
}

// removeRoutesExcept deletes the routes under prefix that keep does not name:
// everything the object no longer asks for, or, with keep nil, everything it
// made. Sync used to only upsert, so a path removed from an Ingress or
// HTTPRoute went on routing to its old backend until the whole object was
// deleted.
func (c *Controller) removeRoutesExcept(ctx context.Context, prefix string, keep map[string]bool) {
	for _, r := range c.routeStore.List(ctx) {
		if !strings.HasPrefix(r.Id, prefix) || keep[r.Id] {
			continue
		}
		if err := c.routeStore.Delete(ctx, r.Id); err != nil {
			logger.L.LogError("failed to delete k8s route", "error", err, "route", r.Id)
		}
	}
}

func (c *Controller) syncHTTPRoute(hr *gatewayv1.HTTPRoute) {
	ctx := c.ctx
	prefix := fmt.Sprintf("k8s-hr-%s-%s", hr.Namespace, hr.Name)
	keep := make(map[string]bool)
	defer func() { c.removeRoutesExcept(ctx, prefix+"-r", keep) }()

	hosts, ok := safeHostnames(hr)
	if !ok {
		return
	}
	for i, rule := range hr.Spec.Rules {
		if len(rule.BackendRefs) == 0 {
			continue
		}
		serviceID := c.syncHTTPRouteBackend(ctx, hr, prefix, rule.BackendRefs[0])
		matches := rule.Matches
		if len(matches) == 0 {
			// No matches means a prefix match on "/", by the Gateway API's
			// definition; ranging over none produced no route at all.
			root := "/"
			matches = []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Value: &root}}}
		}
		for j, match := range matches {
			constraints, ok := matchConstraints(hr, match)
			if !ok {
				continue
			}
			for k, ruleStr := range routeRules(hosts, constraints) {
				id := fmt.Sprintf("%s-r%d-m%d", prefix, i, j)
				// Named as uniquely as it is identified: every match and host
				// of a rule used to share the rule's name, and a route's name
				// is what its metrics and logs are reported under.
				name := fmt.Sprintf("k8s-hr/%s/%s/%d/%d", hr.Namespace, hr.Name, i, j)
				if len(hosts) > 1 {
					id += fmt.Sprintf("-h%d", k)
					name += fmt.Sprintf("/%d", k)
				}
				keep[id] = true
				route := &gateonv1.Route{
					Id:        id,
					Name:      name,
					Rule:      ruleStr,
					Type:      "http",
					ServiceId: serviceID,
				}
				if err := c.routeStore.Update(ctx, route); err != nil {
					logger.L.LogError("failed to sync k8s HTTPRoute route", "error", err, "route", route.Name)
				}
			}
		}
	}
}

// safeHostnames returns the HTTPRoute's hostnames that are safe to put in a
// rule. Hostnames and paths are interpolated into a backtick-quoted rule, so
// a backtick in either escapes the quoting: "a`) || Host(`bank.example.com"
// is a *working* rule that captures another service's traffic, reachable by
// anyone who can create an HTTPRoute. ok is false when every hostname was
// refused, because the route would then match on path alone -- broader than
// what was asked for.
func safeHostnames(hr *gatewayv1.HTTPRoute) (hosts []string, ok bool) {
	for _, h := range hr.Spec.Hostnames {
		if !safeForRule(string(h)) {
			logger.L.LogError("refusing k8s HTTPRoute hostname containing rule metacharacters",
				"namespace", hr.Namespace, "httproute", hr.Name, "hostname", string(h))
			continue
		}
		hosts = append(hosts, string(h))
	}
	return hosts, len(hr.Spec.Hostnames) == 0 || len(hosts) > 0
}

// matchConstraints renders one match as rule clauses. ok is false for a match
// the rule language cannot express -- a regular-expression header, a query
// parameter -- or that carries rule metacharacters: dropping the part it
// cannot express would widen the route, so the match is skipped instead. The
// method and exact headers used to be dropped that way, so a route meant only
// for requests carrying a header took every request on its path.
func matchConstraints(hr *gatewayv1.HTTPRoute, match gatewayv1.HTTPRouteMatch) ([]string, bool) {
	refuse := func(why string) ([]string, bool) {
		logger.L.LogError("skipping k8s HTTPRoute match: "+why, "namespace", hr.Namespace, "httproute", hr.Name)
		return nil, false
	}
	var parts []string
	if match.Path != nil {
		path := "/"
		if match.Path.Value != nil {
			path = *match.Path.Value
		}
		if !safeForRule(path) {
			return refuse("path contains rule metacharacters")
		}
		switch {
		case match.Path.Type == nil || *match.Path.Type == gatewayv1.PathMatchPathPrefix:
			parts = append(parts, fmt.Sprintf("PathPrefix(`%s`)", path))
		case *match.Path.Type == gatewayv1.PathMatchRegularExpression:
			parts = append(parts, fmt.Sprintf("PathRegex(`%s`)", path))
		default:
			parts = append(parts, fmt.Sprintf("Path(`%s`)", path))
		}
	}
	if match.Method != nil {
		parts = append(parts, fmt.Sprintf("Methods(`%s`)", string(*match.Method)))
	}
	for _, h := range match.Headers {
		if h.Type != nil && *h.Type != gatewayv1.HeaderMatchExact {
			return refuse("regular-expression header matches are not supported")
		}
		if !safeForRule(string(h.Name)) || !safeForRule(h.Value) {
			return refuse("header match contains rule metacharacters")
		}
		parts = append(parts, fmt.Sprintf("Headers(`%s`, `%s`)", string(h.Name), h.Value))
	}
	if len(match.QueryParams) > 0 {
		return refuse("query parameter matches are not supported")
	}
	return parts, true
}

// routeRules is one rule per hostname, each carrying the match's
// constraints, or one rule of the constraints alone when the route names no
// hostname. The router reads a single host per Host(), so the rule used to be
// Host(`a`, `b`) -- read as the literal host "a`, `b", which no request
// carries. A rule with no clause at all would match everything, so none is
// returned for it.
func routeRules(hosts, constraints []string) []string {
	tail := strings.Join(constraints, " && ")
	if len(hosts) == 0 {
		if tail == "" {
			return nil
		}
		return []string{tail}
	}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		r := fmt.Sprintf("Host(`%s`)", h)
		if tail != "" {
			r += " && " + tail
		}
		out = append(out, r)
	}
	return out
}

// syncHTTPRouteBackend upserts the service for a rule's first backend and
// returns its ID.
func (c *Controller) syncHTTPRouteBackend(ctx context.Context, hr *gatewayv1.HTTPRoute, prefix string, ref gatewayv1.HTTPBackendRef) string {
	port := int32(80)
	if ref.Port != nil {
		port = int32(*ref.Port)
	}
	serviceID := fmt.Sprintf("%s-svc-%s-%d", prefix, string(ref.Name), port)
	svc := &gateonv1.Service{
		Id:           serviceID,
		Name:         fmt.Sprintf("k8s-hr/%s/%s", hr.Namespace, string(ref.Name)),
		DiscoveryUrl: fmt.Sprintf("dns:%s.%s.svc.cluster.local", string(ref.Name), hr.Namespace),
		BackendType:  "http",
	}
	if err := c.serviceStore.Update(ctx, svc); err != nil {
		logger.L.LogError("failed to sync k8s HTTPRoute service", "error", err, "service", svc.Name)
	}
	return serviceID
}

func (c *Controller) deleteHTTPRoute(hr *gatewayv1.HTTPRoute) {
	// The "-r" is what keeps this from deleting a different HTTPRoute's routes.
	// Route IDs are "<prefix>-r<i>-m<j>", and matching on the prefix alone made
	// "web" a prefix of "web-staging", so removing one HTTPRoute silently tore
	// down another's routing — in the direction that drops traffic.
	c.removeRoutesExcept(c.ctx, fmt.Sprintf("k8s-hr-%s-%s-r", hr.Namespace, hr.Name), nil)
}
