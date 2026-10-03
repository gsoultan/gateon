// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/mgmtaddr"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ErrInvalidService is returned for a service whose settings the gateway could
// not carry out as written (ADR 0043, ADR 0047). The message names the setting
// and says what to change; transports answer it as a client error.
var ErrInvalidService = errors.New("invalid service")

// knownPolicies are the balancers the gateway builds. Anything else used to be
// saved and then balanced round robin, the setting naming one policy and the
// gateway running another.
var knownPolicies = map[string]bool{
	"round_robin": true, "least_conn": true, "weighted_round_robin": true,
	"ai_predictive": true, "intelligent": true,
}

// validateService refuses a service that saves one thing and does another.
func validateService(svc *gateonv1.Service) error {
	policy := config.CanonicalLBPolicy(svc.LoadBalancerPolicy)
	if !knownPolicies[policy] {
		return fmt.Errorf("%w: load balancer policy %q is not one the gateway has; use round_robin, "+
			"least_conn or weighted_round_robin", ErrInvalidService, svc.LoadBalancerPolicy)
	}
	if err := validateWeights(svc, policy); err != nil {
		return err
	}
	return validateHealthCheck(svc)
}

// validateWeights refuses weights the chosen balancer would not read. Round
// robin and weighted round robin honour them; least connections, the
// predictive balancer and every TCP/UDP service do not, so a target saved with
// a different weight from its neighbours there would be balanced as if it had
// none.
func validateWeights(svc *gateonv1.Service, policy string) error {
	distinct := map[int32]bool{}
	for _, t := range svc.GetWeightedTargets() {
		if t.GetWeight() < 0 {
			return fmt.Errorf("%w: target %s has weight %d; a weight is 0 (standby) or more",
				ErrInvalidService, t.GetUrl(), t.GetWeight())
		}
		distinct[t.GetWeight()] = true
	}
	if len(distinct) <= 1 {
		return nil
	}
	if l4 := strings.ToLower(svc.GetBackendType()); l4 == "tcp" || l4 == "udp" {
		return fmt.Errorf("%w: a %s service ignores target weights, and these targets have different "+
			"ones; give every target the same weight", ErrInvalidService, l4)
	}
	if policy != "round_robin" && policy != "weighted_round_robin" {
		return fmt.Errorf("%w: policy %s ignores target weights, and these targets have different ones; "+
			"use round robin to balance by weight, or give every target the same weight", ErrInvalidService, policy)
	}
	return nil
}

// validateHealthCheck refuses an HTTP health check with nothing to request.
// It used to be saved and run no check at all, so a dead backend stayed in
// rotation and the dashboard showed it healthy. Auto, TCP and Custom check by
// connecting when they have no path; an explicit HTTP check needs one.
func validateHealthCheck(svc *gateonv1.Service) error {
	if svc.GetHealthCheckType() == gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP &&
		strings.TrimSpace(svc.GetHealthCheckPath()) == "" {
		return fmt.Errorf("%w: an HTTP health check needs a path (for example /healthz); "+
			"choose Auto or TCP to check each target by connecting to it", ErrInvalidService)
	}
	if svc.GetUnhealthyThreshold() < 0 || svc.GetHealthyThreshold() < 0 {
		return fmt.Errorf("%w: health check thresholds are 0 (the default, 2) or more", ErrInvalidService)
	}
	return nil
}

// validateTargets refuses a target that connects to this gateway's own
// management listener (ADR 0052). Behind a Host() route on a public
// entrypoint, such a service served the dashboard, sign-in and API to the
// internet from loopback, past the listener's bind, its allowlist, its
// per-address cap and the sign-in lockout. Every writer of a service -- REST,
// gRPC, config import, the canary controller -- saves through SaveService, so
// this is the one place it is refused; the connection is refused again when
// it is dialled, for a name that resolves here only later. A UDP service
// never reaches the TCP-only listener and is not checked.
func validateTargets(ctx context.Context, svc *gateonv1.Service) error {
	if strings.EqualFold(svc.GetBackendType(), "udp") {
		return nil
	}
	for _, t := range svc.GetWeightedTargets() {
		if err := mgmtaddr.CheckTarget(ctx, t.GetUrl()); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidService, err)
		}
	}
	return nil
}
