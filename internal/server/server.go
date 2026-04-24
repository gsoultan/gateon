package server

import (
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/redis"
	gtls "github.com/gsoultan/gateon/internal/tls"
)

// Server is the main application container (Dependency Injection).
// Composes config (stores), ProxyCache (runtime), and lifecycle.
type Server struct {
	RouteStore   config.RouteStore
	ServiceStore config.ServiceStore
	EpStore      config.EntryPointStore
	MwStore      config.MiddlewareStore
	TLSOptStore  config.TLSOptionStore
	GlobalStore  config.GlobalConfigStore
	AuthManager  auth.Service
	EbpfManager  ebpf.Manager
	RedisClient  redis.Client
	TLSManager   gtls.TLSManager
	Port         string
	Version      string
	startTime    time.Time

	cache     *ProxyCache
	cacheOnce sync.Once
}

func (s *Server) proxyCache() *ProxyCache {
	s.cacheOnce.Do(func() {
		s.cache = NewProxyCache(s.RouteStore, s.ServiceStore, s.MwStore, s.RedisClient, s.GlobalStore)
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
