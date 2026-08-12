// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain/proxy"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/phantom"
	"github.com/gsoultan/gateon/internal/resource"
	"github.com/gsoultan/gateon/internal/security"
	"github.com/gsoultan/gateon/internal/security/reputation"
	"github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gateon/internal/tls"
)

// ApiServiceConfig holds dependencies for ApiService (Factory pattern).
type ApiServiceConfig struct {
	// Lifetime is the process-lifetime context, cancelled when the gateway
	// begins shutting down. Detached work that must outlive an RPC hangs off
	// this instead of context.Background(), so it is still tied to something.
	// Nil is tolerated (tests build this struct directly) and reads as
	// context.Background().
	Lifetime context.Context

	Version            string
	Routes             config.RouteStore
	Services           config.ServiceStore
	Globals            config.GlobalConfigStore
	EntryPoints        config.EntryPointStore
	Middlewares        config.MiddlewareStore
	TLSOptions         config.TLSOptionStore
	Auth               auth.Service
	Invalidator        proxy.Invalidator
	TLSManager         tls.TLSManager
	RouteStatsProvider RouteStatsProvider
	EbpfManager        ebpf.Manager
	WafUpdater         *middleware.WAFUpdater
	IPReputation       *reputation.IPReputationStore
	ClamAVManager      *security.ClamAVManager
	WafRules           *waf.Store
	WafExceptions      *waf.ExceptionStore
	PhantomCore        phantom.PhantomCore
	Governor           *resource.Governor
}
