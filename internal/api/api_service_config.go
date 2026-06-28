package api

import (
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain/proxy"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/security"
	"github.com/gsoultan/gateon/internal/security/reputation"
	"github.com/gsoultan/gateon/internal/tls"
)

// ApiServiceConfig holds dependencies for ApiService (Factory pattern).
type ApiServiceConfig struct {
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
}
