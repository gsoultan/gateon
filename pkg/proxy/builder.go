package proxy

import (
	"cmp"
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ProxyHandlerBuilder builds a ProxyHandler stepwise (Builder pattern).
type ProxyHandlerBuilder struct {
	route               *gateonv1.Route
	serviceStore        config.ServiceStore
	lbFactory           LoadBalancerFactory
	targets             []*gateonv1.Target
	lb                  LoadBalancer
	discoveryURL        string
	healthCheckPath     string
	healthCheckPort     int32
	healthCheckProtocol string
	healthCheckType     gateonv1.HealthCheckType
	routeType           string
	transportFactory    *backendTransportFactory
	healthCheckClient   *http.Client
	tlsConfig           *tls.Config
	transportConfig     *TransportConfig
	tlsClientConfig     *gateonv1.TlsClientConfig
}

// NewProxyHandlerBuilder creates a builder for the given route.
func NewProxyHandlerBuilder(rt *gateonv1.Route, serviceStore config.ServiceStore, lbFactory LoadBalancerFactory) *ProxyHandlerBuilder {
	b := &ProxyHandlerBuilder{
		route:        rt,
		serviceStore: serviceStore,
		lbFactory:    lbFactory,
		routeType:    rt.Type,
	}
	if lbFactory == nil {
		b.lbFactory = NewDefaultLoadBalancerFactory()
	}
	return b
}

// SetTransportConfig sets connection pooling config for HTTP/1.1 transports.
func (b *ProxyHandlerBuilder) SetTransportConfig(cfg *TransportConfig) *ProxyHandlerBuilder {
	b.transportConfig = cfg
	return b
}

func (b *ProxyHandlerBuilder) resolveService() {
	if b.route.ServiceId == "" || b.serviceStore == nil {
		b.targets = []*gateonv1.Target{}
		b.lb = b.lbFactory.Create("", b.targets)
		return
	}
	svc, ok := b.serviceStore.Get(context.Background(), b.route.ServiceId)
	if !ok || svc == nil {
		b.targets = []*gateonv1.Target{}
		b.lb = b.lbFactory.Create("", b.targets)
		return
	}
	b.targets = svc.WeightedTargets
	b.discoveryURL = svc.DiscoveryUrl
	b.healthCheckPath = svc.HealthCheckPath
	b.healthCheckPort = svc.HealthCheckPort
	b.healthCheckProtocol = svc.HealthCheckProtocol
	b.healthCheckType = svc.HealthCheckType
	b.tlsClientConfig = svc.TlsClientConfig
	policy := svc.LoadBalancerPolicy
	if policy == "" {
		policy = "round_robin"
	}
	b.lb = b.lbFactory.Create(policy, b.targets)
}

func (b *ProxyHandlerBuilder) buildTransport() {
	tlsCfg, err := gtls.CreateTLSClientConfig(b.tlsClientConfig)
	if err != nil {
		logger.L.Warn().Err(err).Msg("failed to create tls client config; using insecure fallback")
		tlsCfg = &tls.Config{InsecureSkipVerify: true}
	}
	b.tlsConfig = tlsCfg
	selector, err := newTLSClientIdentitySelector(b.tlsClientConfig)
	if err != nil {
		logger.L.Warn().Err(err).Msg("failed to load one or more dynamic tls client identities")
	}
	b.transportFactory = newBackendTransportFactory(tlsCfg, b.transportConfig, selector)

	b.healthCheckClient = &http.Client{
		Timeout:   5 * time.Second,
		Transport: b.transportFactory.HealthCheckTransport(),
	}
}

// Build constructs the ProxyHandler.
func (b *ProxyHandlerBuilder) Build() *ProxyHandler {
	if b.lb == nil {
		b.resolveService()
	}
	if b.transportFactory == nil {
		b.buildTransport()
	}

	// Default health check type based on protocol if unspecified
	if b.healthCheckType == gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_UNSPECIFIED {
		if strings.EqualFold(b.routeType, "tcp") {
			b.healthCheckType = gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP
		}
		for _, t := range b.targets {
			lowerURL := strings.ToLower(t.Url)
			if strings.HasPrefix(lowerURL, "h2://") || strings.HasPrefix(lowerURL, "h2c://") {
				b.healthCheckType = gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_GRPC
				break
			}
			if b.healthCheckType == gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_UNSPECIFIED &&
				(strings.HasPrefix(lowerURL, "tcp://") || !strings.Contains(lowerURL, "://")) {
				b.healthCheckType = gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP
			}
		}
		// If still unspecified, default to HTTP
		if b.healthCheckType == gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_UNSPECIFIED {
			b.healthCheckType = gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP
		}
	}

	h := &ProxyHandler{
		lb:                  b.lb,
		routeType:           b.routeType,
		healthCheckPath:     b.healthCheckPath,
		healthCheckPort:     b.healthCheckPort,
		healthCheckProtocol: b.healthCheckProtocol,
		healthCheckType:     b.healthCheckType,
		discoveryURL:        b.discoveryURL,
		routeName:           cmp.Or(b.route.Name, b.route.Id),
		stopDiscovery:       make(chan struct{}),
		stopHealthCheck:     make(chan struct{}),
		transport:           &targetAwareRoundTripper{factory: b.transportFactory},
		transportFactory:    b.transportFactory,
		healthCheckClient:   b.healthCheckClient,
		tlsConfig:           b.tlsConfig,
	}
	if h.discoveryURL != "" {
		go h.runDiscovery()
	}

	// Health check is enabled if:
	// 1. Type is HTTP and path is set
	// 2. Type is gRPC (path is optional service name)
	enableHC := false
	if h.healthCheckType == gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP && h.healthCheckPath != "" {
		enableHC = true
	} else if h.healthCheckType == gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_GRPC {
		enableHC = true
	} else if h.healthCheckType == gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP {
		enableHC = true
	} else if h.healthCheckType == gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_CUSTOM {
		enableHC = h.healthCheckPath != "" || h.healthCheckProtocol != ""
	}

	if enableHC && (len(b.targets) > 0 || b.discoveryURL != "") {
		go h.runHealthCheck()
	}
	return h
}
