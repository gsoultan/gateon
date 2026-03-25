package server

import (
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	redigo "github.com/redis/go-redis/v9"
)

// ServerOption configures the Server (functional options / builder pattern).
type ServerOption func(*Server) error

// WithRouteRegistry sets the route store (DIP: accepts implementation, stores interface).
func WithRouteRegistry(r *config.RouteRegistry) ServerOption {
	return func(s *Server) error {
		s.RouteStore = r
		return nil
	}
}

// WithServiceRegistry sets the service store.
func WithServiceRegistry(r *config.ServiceRegistry) ServerOption {
	return func(s *Server) error {
		s.ServiceStore = r
		return nil
	}
}

// WithEntryPointRegistry sets the entrypoint store.
func WithEntryPointRegistry(r *config.EntryPointRegistry) ServerOption {
	return func(s *Server) error {
		s.EpStore = r
		return nil
	}
}

// WithMiddlewareRegistry sets the middleware store.
func WithMiddlewareRegistry(r *config.MiddlewareRegistry) ServerOption {
	return func(s *Server) error {
		s.MwStore = r
		return nil
	}
}

// WithTLSOptionRegistry sets the TLS option store.
func WithTLSOptionRegistry(r *config.TLSOptionRegistry) ServerOption {
	return func(s *Server) error {
		s.TLSOptStore = r
		return nil
	}
}

// WithGlobalRegistry sets the global config store.
func WithGlobalRegistry(r *config.GlobalRegistry) ServerOption {
	return func(s *Server) error {
		s.GlobalStore = r
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
func WithRedisClient(c *redigo.Client) ServerOption {
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
