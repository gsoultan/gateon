package proxy

import (
	"strings"

	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

// LoadBalancerFactory creates a LoadBalancer for the given policy and targets.
// Implements Abstract Factory pattern; proxy package depends on this abstraction.
type LoadBalancerFactory interface {
	Create(policy string, targets []*gateonv1.Target) LoadBalancer
}

// DefaultLoadBalancerFactory creates standard load balancers based on policy.
type DefaultLoadBalancerFactory struct{}

// NewDefaultLoadBalancerFactory returns the default factory.
func NewDefaultLoadBalancerFactory() LoadBalancerFactory {
	return &DefaultLoadBalancerFactory{}
}

// Create returns a LoadBalancer for the given policy.
// Policy: "least_conn", "weighted_round_robin", or default round-robin.
func (f *DefaultLoadBalancerFactory) Create(policy string, targets []*gateonv1.Target) LoadBalancer {
	if targets == nil {
		targets = []*gateonv1.Target{}
	}
	urls := make([]string, len(targets))
	for i, t := range targets {
		urls[i] = t.Url
	}
	switch strings.ToLower(policy) {
	case "least_conn":
		return NewLeastConnLB(urls)
	case "weighted_round_robin":
		return NewWeightedRoundRobinLB(targets)
	default:
		return NewRoundRobinLB(urls)
	}
}
