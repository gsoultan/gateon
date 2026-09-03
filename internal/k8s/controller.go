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
func NewController(client kubernetes.Interface, gatewayClient gatewayclient.Interface, routeStore config.RouteStore, serviceStore config.ServiceStore) *Controller {
	factory := informers.NewSharedInformerFactory(client, 30*time.Second)
	informer := factory.Networking().V1().Ingresses().Informer()

	gwFactory := gatewayinformers.NewSharedInformerFactory(gatewayClient, 30*time.Second)
	gwInformer := gwFactory.Gateway().V1().HTTPRoutes().Informer()

	c := &Controller{
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
		AddFunc: func(obj any) {
			c.syncIngress(obj.(*networkingv1.Ingress))
		},
		UpdateFunc: func(oldObj, newObj any) {
			c.syncIngress(newObj.(*networkingv1.Ingress))
		},
		DeleteFunc: func(obj any) {
			c.deleteIngress(obj.(*networkingv1.Ingress))
		},
	})

	_, _ = gwInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			c.syncHTTPRoute(obj.(*gatewayv1.HTTPRoute))
		},
		UpdateFunc: func(oldObj, newObj any) {
			c.syncHTTPRoute(newObj.(*gatewayv1.HTTPRoute))
		},
		DeleteFunc: func(obj any) {
			c.deleteHTTPRoute(obj.(*gatewayv1.HTTPRoute))
		},
	})

	return c
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
	ctx := context.Background()
	ingressID := fmt.Sprintf("k8s-%s-%s", ing.Namespace, ing.Name)

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
				Name:      fmt.Sprintf("k8s/%s/%s/%d", ing.Namespace, ing.Name, i),
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
	ctx := context.Background()
	ingressID := fmt.Sprintf("k8s-%s-%s", ing.Namespace, ing.Name)

	// Since we don't know how many rules/paths it had, we'd need to list and filter.
	// For simplicity, we can use a naming convention.
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
	prefix := ingressID + "-r"
	routes := c.routeStore.List(ctx)
	for _, r := range routes {
		if strings.HasPrefix(r.Id, prefix) {
			if err := c.routeStore.Delete(ctx, r.Id); err != nil {
				logger.L.LogError("failed to delete k8s ingress route", "error", err, "route", r.Id)
			}
		}
	}
}

func (c *Controller) syncHTTPRoute(hr *gatewayv1.HTTPRoute) {
	ctx := context.Background()
	routeIDPrefix := fmt.Sprintf("k8s-hr-%s-%s", hr.Namespace, hr.Name)

	for i, rule := range hr.Spec.Rules {
		for j, match := range rule.Matches {
			routeID := fmt.Sprintf("%s-r%d-m%d", routeIDPrefix, i, j)

			// Hostnames and paths are interpolated into a backtick-quoted rule,
			// so a backtick in either escapes the quoting. syncIngress already
			// guards this; the Gateway API path never did, and it is reachable by
			// anyone who can create an HTTPRoute. A hostname of
			// "a`) || Host(`bank.example.com" is a *working* rule that captures
			// another service's traffic.
			var ruleParts []string
			if len(hr.Spec.Hostnames) > 0 {
				hosts := make([]string, 0, len(hr.Spec.Hostnames))
				for _, h := range hr.Spec.Hostnames {
					if !safeForRule(string(h)) {
						logger.L.LogError("refusing k8s HTTPRoute hostname containing rule metacharacters",
							"namespace", hr.Namespace, "httproute", hr.Name, "hostname", string(h))
						continue
					}
					hosts = append(hosts, string(h))
				}
				// Every hostname rejected means the rule would match on path
				// alone, which is broader than what was asked for, so the match
				// is skipped rather than widened.
				if len(hosts) == 0 {
					continue
				}
				ruleParts = append(ruleParts, fmt.Sprintf("Host(`%s`)", strings.Join(hosts, "`, `")))
			}

			if match.Path != nil {
				path := "/"
				if match.Path.Value != nil {
					path = *match.Path.Value
				}
				if !safeForRule(path) {
					logger.L.LogError("refusing k8s HTTPRoute path containing rule metacharacters",
						"namespace", hr.Namespace, "httproute", hr.Name, "path", path)
					continue
				}
				if match.Path.Type == nil || *match.Path.Type == gatewayv1.PathMatchPathPrefix {
					ruleParts = append(ruleParts, fmt.Sprintf("PathPrefix(`%s`)", path))
				} else {
					ruleParts = append(ruleParts, fmt.Sprintf("Path(`%s`)", path))
				}
			}

			// A match that produced no constraints would become an empty rule,
			// which matches everything.
			if len(ruleParts) == 0 {
				continue
			}

			ruleStr := strings.Join(ruleParts, " && ")
			if len(rule.BackendRefs) == 0 {
				continue
			}

			// For simplicity, handle first backend
			ref := rule.BackendRefs[0]
			port := int32(80)
			if ref.Port != nil {
				port = int32(*ref.Port)
			}
			serviceID := fmt.Sprintf("%s-svc-%s-%d", routeIDPrefix, string(ref.Name), port)

			svc := &gateonv1.Service{
				Id:           serviceID,
				Name:         fmt.Sprintf("k8s-hr/%s/%s", hr.Namespace, string(ref.Name)),
				DiscoveryUrl: fmt.Sprintf("dns:%s.%s.svc.cluster.local", string(ref.Name), hr.Namespace),
				BackendType:  "http",
			}
			if err := c.serviceStore.Update(ctx, svc); err != nil {
				logger.L.LogError("failed to sync k8s HTTPRoute service", "error", err, "service", svc.Name)
			}

			route := &gateonv1.Route{
				Id:        routeID,
				Name:      fmt.Sprintf("k8s-hr/%s/%s/%d", hr.Namespace, hr.Name, i),
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

func (c *Controller) deleteHTTPRoute(hr *gatewayv1.HTTPRoute) {
	ctx := context.Background()
	// The "-r" is what keeps this from deleting a different HTTPRoute's routes.
	// Route IDs are "<prefix>-r<i>-m<j>", and matching on the prefix alone made
	// "web" a prefix of "web-staging", so removing one HTTPRoute silently tore
	// down another's routing — in the direction that drops traffic. deleteIngress
	// was fixed for exactly this; the Gateway API path was left behind.
	prefix := fmt.Sprintf("k8s-hr-%s-%s-r", hr.Namespace, hr.Name)
	routes := c.routeStore.List(ctx)
	for _, r := range routes {
		if strings.HasPrefix(r.Id, prefix) {
			if err := c.routeStore.Delete(ctx, r.Id); err != nil {
				logger.L.LogError("failed to delete k8s HTTPRoute route", "error", err, "route", r.Id)
			}
		}
	}
}
