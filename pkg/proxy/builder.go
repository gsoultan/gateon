package proxy

import (
	"cmp"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"github.com/gsoultan/gateon/internal/config"
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
	transport           http.RoundTripper
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
	useH2 := false
	useH2C := false
	useH3 := false
	for _, t := range b.targets {
		lowerURL := strings.ToLower(t.Url)
		if strings.HasPrefix(lowerURL, "h2c://") {
			useH2C = true
		}
		if strings.HasPrefix(lowerURL, "h2://") {
			useH2 = true
		}
		if strings.HasPrefix(lowerURL, "h3://") {
			useH3 = true
		}
	}
	tlsCfg, _ := gtls.CreateTLSClientConfig(b.tlsClientConfig)
	b.tlsConfig = tlsCfg

	// Create health check client with a transport that supports H1/H2
	tHealth := http.DefaultTransport.(*http.Transport).Clone()
	tHealth.TLSClientConfig = tlsCfg
	b.healthCheckClient = &http.Client{
		Timeout:   5 * time.Second,
		Transport: tHealth,
	}

	switch {
	case useH3:
		b.transport = &http3.Transport{
			TLSClientConfig: tlsCfg,
		}
	case useH2C:
		b.transport = &http2.Transport{
			AllowHTTP:       true,
			ReadIdleTimeout: 30 * time.Second,
			PingTimeout:     15 * time.Second,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		}
	case useH2:
		b.transport = &http2.Transport{
			TLSClientConfig: tlsCfg,
			ReadIdleTimeout: 30 * time.Second,
			PingTimeout:     15 * time.Second,
		}
	default:
		t := http.DefaultTransport.(*http.Transport).Clone()
		tc := b.transportConfig
		if tc == nil {
			tc = &TransportConfig{}
		}
		t.MaxIdleConns = tc.maxIdleConns()
		t.MaxIdleConnsPerHost = tc.maxIdleConnsPerHost()
		t.IdleConnTimeout = tc.idleConnTimeout()
		t.ForceAttemptHTTP2 = true
		t.TLSClientConfig = tlsCfg
		b.transport = t
	}
}

// Build constructs the ProxyHandler.
func (b *ProxyHandlerBuilder) Build() *ProxyHandler {
	if b.lb == nil {
		b.resolveService()
	}
	if b.transport == nil {
		b.buildTransport()
	}

	// Default health check type based on protocol if unspecified
	if b.healthCheckType == gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_UNSPECIFIED {
		for _, t := range b.targets {
			lowerURL := strings.ToLower(t.Url)
			if strings.HasPrefix(lowerURL, "h2://") || strings.HasPrefix(lowerURL, "h2c://") {
				b.healthCheckType = gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_GRPC
				break
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
		transport:           b.transport,
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
	}

	if enableHC && (len(b.targets) > 0 || b.discoveryURL != "") {
		urls := make([]string, len(b.targets))
		for i, t := range b.targets {
			urls[i] = t.Url
		}
		go h.runHealthCheck(urls)
	}
	return h
}
