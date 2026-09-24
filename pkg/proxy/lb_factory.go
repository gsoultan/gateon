// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
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
// Policy: "least_conn", "weighted_round_robin", "ai_predictive", or default round-robin.
func (f *DefaultLoadBalancerFactory) Create(policy string, targets []*gateonv1.Target) LoadBalancer {
	if targets == nil {
		targets = []*gateonv1.Target{}
	}
	// Built from the whole Target, not from its URL. The URL-only constructors
	// drop proxy_protocol_enabled and proxy_protocol_version, and only
	// discovery ever replaced that first target set, so a service without a
	// discovery URL never sent the PROXY header however it was configured.
	switch config.CanonicalLBPolicy(policy) {
	case "least_conn":
		lb := NewLeastConnLB(nil)
		lb.UpdateWeightedTargets(targets)
		return lb
	case "weighted_round_robin":
		return NewWeightedRoundRobinLB(targets)
	case "ai_predictive", "intelligent":
		return NewAIPredictiveLB(targets)
	default:
		lb := NewRoundRobinLB(nil)
		lb.UpdateWeightedTargets(targets)
		return lb
	}
}
