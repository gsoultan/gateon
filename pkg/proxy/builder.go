package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ProxyHandlerBuilder builds a ProxyHandler stepwise (Builder pattern).
type ProxyHandlerBuilder struct {
	route           *gateonv1.Route
	serviceStore    config.ServiceStore
	lbFactory       LoadBalancerFactory
	targets         []*gateonv1.Target
	lb              LoadBalancer
	healthCheckPath string
	routeType       string
	transport       http.RoundTripper
	transportConfig *TransportConfig
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
	b.healthCheckPath = svc.HealthCheckPath
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
	switch {
	case useH3:
		b.transport = &http3.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
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
	h := &ProxyHandler{
		lb:              b.lb,
		routeType:       b.routeType,
		healthCheckPath: b.healthCheckPath,
		stopHealthCheck: make(chan struct{}),
		transport:       b.transport,
	}
	if h.healthCheckPath != "" && len(b.targets) > 0 {
		urls := make([]string, len(b.targets))
		for i, t := range b.targets {
			urls[i] = t.Url
		}
		go h.runHealthCheck(urls)
	}
	return h
}
