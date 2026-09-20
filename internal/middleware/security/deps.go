// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/security/reputation"
)

// Deps is what the security middlewares used to read off *Factory.
//
// A struct rather than five parameters on every constructor: the WAF alone
// needs four of them, and a positional list that long is the kind of signature
// where two arguments get swapped and everything still compiles. Named fields
// also make it obvious at the call site in factory.go which of the factory's
// state each middleware actually depends on.
type Deps struct {
	GlobalStore config.GlobalConfigStore
	EbpfManager ebpf.Manager
	Reputation  *reputation.IPReputationStore
	DataDir     string

	// RouteType is the route's declared protocol. It stands in for the
	// factory's IsGRPCRoute method, which is one string comparison and does
	// not justify reaching back into package middleware for it.
	RouteType string
}

// IsGRPCRoute reports whether this route is configured as gRPC, which unlocks
// the WAF's transport relaxations. It reads Deps.RouteType, which comes from
// gateon's own route configuration -- never from a request header, because a
// client that could name its own transport could ask for the relaxations.
func (d Deps) IsGRPCRoute() bool {
	return strings.EqualFold(strings.TrimSpace(d.RouteType), "grpc")
}

// NewHoneypot builds the honeypot middleware from a route's config map.
//
// It exists because parseHoneypotConfig is unexported and factory.go used to
// call it inline. A constructor keeps the parsing with the thing it parses for,
// which is the same reason the other eight moved.
func NewHoneypot(cfg map[string]string) kind.Middleware {
	return Honeypot(parseHoneypotConfig(cfg))
}
