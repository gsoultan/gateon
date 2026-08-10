// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/phantom"
	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/internal/resource"
	gtls "github.com/gsoultan/gateon/internal/tls"
	"github.com/rs/cors"
)

// Server is the main application container (Dependency Injection).
// Composes config (stores), ProxyCache (runtime), and lifecycle.
type Server struct {
	RouteStore    config.RouteStore
	ServiceStore  config.ServiceStore
	EpStore       config.EntryPointStore
	MwStore       config.MiddlewareStore
	TLSOptStore   config.TLSOptionStore
	GlobalStore   config.GlobalConfigStore
	AuthManager   auth.Service
	EbpfManager   ebpf.Manager
	RedisClient   redis.Client
	TLSManager    gtls.TLSManager
	IPReputation  any // reputation.IPReputationStore
	WafUpdater    any // middleware.WAFUpdater (interface to avoid cyclic import)
	ClamAVManager any // security.ClamAVManager
	WafRules      any // waf.Store
	Phantom       phantom.PhantomCore
	Governor      *resource.Governor
	Logger        logger.Logger
	Port          string
	Version       string
	startTime     time.Time
	MgmtCORS      *cors.Cors

	cache     *ProxyCache
	cacheOnce sync.Once
}

func (s *Server) proxyCache() *ProxyCache {
	s.cacheOnce.Do(func() {
		s.cache = NewProxyCache(s.RouteStore, s.ServiceStore, s.MwStore, s.RedisClient, s.GlobalStore, s.EbpfManager, s.IPReputation)
	})
	return s.cache
}

// NewServer builds a Server with the given options (Builder / Functional Options pattern).
func NewServer(opts ...ServerOption) (*Server, error) {
	s := &Server{startTime: time.Now()}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	if s.Port == "" {
		s.Port = "8080"
	}
	if s.Version == "" {
		s.Version = "dev"
	}
	return s, nil
}

// StartTime returns when the server was created (for uptime).
func (s *Server) StartTime() time.Time { return s.startTime }

// PurgeCache clears the proxy cache.
func (s *Server) PurgeCache() {
	s.proxyCache().Purge()
}

// Close closes all server resources.
func (s *Server) Close() error {
	if auth.Available(s.AuthManager) {
		_ = s.AuthManager.Close()
	}
	if s.Phantom != nil {
		_ = s.Phantom.Close()
	}
	if s.Governor != nil {
		_ = s.Governor.Stop()
	}
	return nil
}
