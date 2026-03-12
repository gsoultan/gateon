package server

import (
	"net/http"
	"sync"
	"time"

	"github.com/gateon/gateon/internal/auth"
	"github.com/gateon/gateon/internal/config"
	"github.com/redis/go-redis/v9"
)

// Server is the main application container (Dependency Injection).
// All registries, proxy cache, and config are held here.
type Server struct {
	RouteReg    *config.RouteRegistry
	ServiceReg  *config.ServiceRegistry
	EpReg       *config.EntryPointRegistry
	MwReg       *config.MiddlewareRegistry
	TLSOptReg   *config.TLSOptionRegistry
	GlobalReg   *config.GlobalRegistry
	AuthManager *auth.Manager
	RedisClient *redis.Client
	Port        string
	Version     string

	Proxies   map[string]http.Handler
	ProxiesMu *sync.RWMutex

	startTime time.Time
}

// NewServer builds a Server with the given options (Builder / Functional Options pattern).
func NewServer(opts ...ServerOption) (*Server, error) {
	s := &Server{
		Proxies:   make(map[string]http.Handler),
		ProxiesMu: &sync.RWMutex{},
		startTime: time.Now(),
	}
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
