package server

import (
	"github.com/gateon/gateon/internal/auth"
	"github.com/gateon/gateon/internal/config"
	"github.com/redis/go-redis/v9"
)

// ServerOption configures the Server (functional options / builder pattern).
type ServerOption func(*Server) error

// WithRouteRegistry sets the route registry.
func WithRouteRegistry(r *config.RouteRegistry) ServerOption {
	return func(s *Server) error {
		s.RouteReg = r
		return nil
	}
}

// WithServiceRegistry sets the service registry.
func WithServiceRegistry(r *config.ServiceRegistry) ServerOption {
	return func(s *Server) error {
		s.ServiceReg = r
		return nil
	}
}

// WithEntryPointRegistry sets the entrypoint registry.
func WithEntryPointRegistry(r *config.EntryPointRegistry) ServerOption {
	return func(s *Server) error {
		s.EpReg = r
		return nil
	}
}

// WithMiddlewareRegistry sets the middleware registry.
func WithMiddlewareRegistry(r *config.MiddlewareRegistry) ServerOption {
	return func(s *Server) error {
		s.MwReg = r
		return nil
	}
}

// WithTLSOptionRegistry sets the TLS option registry.
func WithTLSOptionRegistry(r *config.TLSOptionRegistry) ServerOption {
	return func(s *Server) error {
		s.TLSOptReg = r
		return nil
	}
}

// WithGlobalRegistry sets the global config registry.
func WithGlobalRegistry(r *config.GlobalRegistry) ServerOption {
	return func(s *Server) error {
		s.GlobalReg = r
		return nil
	}
}

// WithAuthManager sets the auth manager (may be nil if auth disabled).
func WithAuthManager(a *auth.Manager) ServerOption {
	return func(s *Server) error {
		s.AuthManager = a
		return nil
	}
}

// WithRedisClient sets the Redis client.
func WithRedisClient(c *redis.Client) ServerOption {
	return func(s *Server) error {
		s.RedisClient = c
		return nil
	}
}

// WithPort sets the default port.
func WithPort(port string) ServerOption {
	return func(s *Server) error {
		s.Port = port
		return nil
	}
}

// WithVersion sets the version string.
func WithVersion(v string) ServerOption {
	return func(s *Server) error {
		s.Version = v
		return nil
	}
}
