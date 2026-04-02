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

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
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

	gwInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
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

func (c *Controller) syncIngress(ing *networkingv1.Ingress) {
	ctx := context.Background()
	ingressID := fmt.Sprintf("k8s-%s-%s", ing.Namespace, ing.Name)

	for i, rule := range ing.Spec.Rules {
		host := rule.Host
		if rule.HTTP == nil {
			continue
		}
		for j, path := range rule.HTTP.Paths {
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
				logger.L.Error().Err(err).Str("service_id", serviceID).Msg("failed to sync k8s service")
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
				logger.L.Error().Err(err).Str("route", route.Name).Msg("failed to sync k8s route")
			}
		}
	}
}

func (c *Controller) deleteIngress(ing *networkingv1.Ingress) {
	ctx := context.Background()
	ingressID := fmt.Sprintf("k8s-%s-%s", ing.Namespace, ing.Name)

	// Since we don't know how many rules/paths it had, we'd need to list and filter.
	// For simplicity, we can use a naming convention.
	routes := c.routeStore.List(ctx)
	for _, r := range routes {
		if strings.HasPrefix(r.Id, ingressID) {
			_ = c.routeStore.Delete(ctx, r.Id)
		}
	}
}

func (c *Controller) syncHTTPRoute(hr *gatewayv1.HTTPRoute) {
	ctx := context.Background()
	routeIDPrefix := fmt.Sprintf("k8s-hr-%s-%s", hr.Namespace, hr.Name)

	for i, rule := range hr.Spec.Rules {
		for j, match := range rule.Matches {
			routeID := fmt.Sprintf("%s-r%d-m%d", routeIDPrefix, i, j)

			var ruleParts []string
			if len(hr.Spec.Hostnames) > 0 {
				hosts := make([]string, len(hr.Spec.Hostnames))
				for k, h := range hr.Spec.Hostnames {
					hosts[k] = string(h)
				}
				ruleParts = append(ruleParts, fmt.Sprintf("Host(`%s`)", strings.Join(hosts, "`, `")))
			}

			if match.Path != nil {
				path := "/"
				if match.Path.Value != nil {
					path = *match.Path.Value
				}
				if match.Path.Type == nil || *match.Path.Type == gatewayv1.PathMatchPathPrefix {
					ruleParts = append(ruleParts, fmt.Sprintf("PathPrefix(`%s`)", path))
				} else {
					ruleParts = append(ruleParts, fmt.Sprintf("Path(`%s`)", path))
				}
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
			_ = c.serviceStore.Update(ctx, svc)

			route := &gateonv1.Route{
				Id:        routeID,
				Name:      fmt.Sprintf("k8s-hr/%s/%s/%d", hr.Namespace, hr.Name, i),
				Rule:      ruleStr,
				Type:      "http",
				ServiceId: serviceID,
			}
			_ = c.routeStore.Update(ctx, route)
		}
	}
}

func (c *Controller) deleteHTTPRoute(hr *gatewayv1.HTTPRoute) {
	ctx := context.Background()
	prefix := fmt.Sprintf("k8s-hr-%s-%s", hr.Namespace, hr.Name)
	routes := c.routeStore.List(ctx)
	for _, r := range routes {
		if strings.HasPrefix(r.Id, prefix) {
			_ = c.routeStore.Delete(ctx, r.Id)
		}
	}
}
