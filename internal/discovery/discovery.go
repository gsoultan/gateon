package discovery

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/hashicorp/consul/api"
	"go.etcd.io/etcd/client/v3"
)

// Provider resolves targets from a discovery URL.
type Provider interface {
	Resolve(ctx context.Context, discoveryURL string) ([]*gateonv1.Target, error)
}

// Resolver resolves targets using multiple providers based on scheme.
type Resolver struct {
	providers map[string]Provider
}

// NewResolver creates a new Resolver with default providers.
func NewResolver() *Resolver {
	return &Resolver{
		providers: map[string]Provider{
			"dns":    &DNSProvider{},
			"consul": &ConsulProvider{},
			"etcd":   &EtcdProvider{},
			"mdns":   &MDNSProvider{},
			"eureka": &EurekaProvider{},
		},
	}
}

// Resolve resolves the discovery URL to a list of targets.
func (r *Resolver) Resolve(ctx context.Context, url string) ([]*gateonv1.Target, error) {
	parts := strings.SplitN(url, ":", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid discovery URL: %s", url)
	}
	scheme, target := parts[0], parts[1]
	p, ok := r.providers[scheme]
	if !ok {
		return nil, fmt.Errorf("unsupported discovery scheme: %s", scheme)
	}
	return p.Resolve(ctx, target)
}

// DNSProvider resolves targets using DNS SRV records.
type DNSProvider struct{}

func (p *DNSProvider) Resolve(ctx context.Context, target string) ([]*gateonv1.Target, error) {
	// Format: service.name or _service._proto.name
	var service, proto, name string
	parts := strings.Split(target, ".")
	if len(parts) >= 3 && strings.HasPrefix(parts[0], "_") && strings.HasPrefix(parts[1], "_") {
		service = strings.TrimPrefix(parts[0], "_")
		proto = strings.TrimPrefix(parts[1], "_")
		name = strings.Join(parts[2:], ".")
	} else {
		// Default to HTTP
		service = "http"
		proto = "tcp"
		name = target
	}

	_, addrs, err := net.LookupSRV(service, proto, name)
	if err != nil {
		// Fallback to A/AAAA record if SRV fails and it's not a proper SRV name
		ips, err := net.LookupIP(name)
		if err != nil {
			return nil, err
		}
		targets := make([]*gateonv1.Target, len(ips))
		for i, ip := range ips {
			targets[i] = &gateonv1.Target{
				Url:      fmt.Sprintf("http://%s", ip.String()), // Default to http
				Weight:   1,
				Protocol: "http",
			}
		}
		return targets, nil
	}

	targets := make([]*gateonv1.Target, len(addrs))
	for i, addr := range addrs {
		targetName := strings.TrimSuffix(addr.Target, ".")
		targets[i] = &gateonv1.Target{
			Url:      fmt.Sprintf("http://%s:%d", targetName, addr.Port),
			Weight:   int32(addr.Priority*10 + addr.Weight), // Simple weight calculation
			Protocol: "http",
		}
	}
	return targets, nil
}

// ConsulProvider resolves targets using Consul service discovery.
type ConsulProvider struct{}

func (p *ConsulProvider) Resolve(ctx context.Context, target string) ([]*gateonv1.Target, error) {
	config := api.DefaultConfig()
	// Check for CONSUL_HTTP_ADDR etc in env.
	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}

	services, _, err := client.Health().Service(target, "", true, nil)
	if err != nil {
		return nil, err
	}

	targets := make([]*gateonv1.Target, len(services))
	for i, entry := range services {
		addr := entry.Service.Address
		if addr == "" {
			addr = entry.Node.Address
		}
		targets[i] = &gateonv1.Target{
			Url:      fmt.Sprintf("http://%s:%d", addr, entry.Service.Port),
			Weight:   1,
			Protocol: "http",
		}
	}
	return targets, nil
}

// EtcdProvider resolves targets using Etcd key-value store.
// It expects targets to be stored as JSON serialized gateonv1.Target under the given prefix.
type EtcdProvider struct{}

func (p *EtcdProvider) Resolve(ctx context.Context, target string) ([]*gateonv1.Target, error) {
	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"localhost:2379"}, // Default
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	defer client.Close()

	resp, err := client.Get(ctx, target, clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}

	targets := make([]*gateonv1.Target, len(resp.Kvs))
	for i, kv := range resp.Kvs {
		// For simplicity, we assume the value is just the URL, or we could parse JSON.
		// Let's assume it's the URL for now to be lean, but in production it might be more complex.
		targets[i] = &gateonv1.Target{
			Url:      string(kv.Value),
			Weight:   1,
			Protocol: "http",
		}
	}
	return targets, nil
}

// MDNSProvider resolves targets using mDNS (.local).
type MDNSProvider struct{}

func (p *MDNSProvider) Resolve(ctx context.Context, target string) ([]*gateonv1.Target, error) {
	// Note: For full mDNS support, a library like github.com/hashicorp/mdns is recommended.
	// This basic implementation relies on the OS resolver which often handles .local.
	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, fmt.Errorf("mdns resolve %s: %w", target, err)
	}
	targets := make([]*gateonv1.Target, len(ips))
	for i, ip := range ips {
		targets[i] = &gateonv1.Target{
			Url:      fmt.Sprintf("http://%s", ip.String()),
			Weight:   1,
			Protocol: "http",
		}
	}
	return targets, nil
}

// EurekaProvider resolves targets using Netflix Eureka.
type EurekaProvider struct{}

func (p *EurekaProvider) Resolve(ctx context.Context, target string) ([]*gateonv1.Target, error) {
	// Eureka discovery logic would go here.
	// Typically involves: GET /eureka/v2/apps/{target}
	return nil, fmt.Errorf("eureka provider not yet fully implemented")
}
