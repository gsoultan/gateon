// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/phantom"
	"github.com/gsoultan/gateon/internal/resource"
	redigo "github.com/redis/go-redis/v9"
)

// ServerOption configures the Server (functional options / builder pattern).
type ServerOption func(*Server) error

// WithRouteRegistry sets the route store (DIP: accepts implementation, stores interface).
func WithRouteRegistry(r config.RouteStore) ServerOption {
	return func(s *Server) error {
		s.RouteStore = r
		return nil
	}
}

// WithServiceRegistry sets the service store.
func WithServiceRegistry(r config.ServiceStore) ServerOption {
	return func(s *Server) error {
		s.ServiceStore = r
		return nil
	}
}

// WithEntryPointRegistry sets the entrypoint store.
func WithEntryPointRegistry(r config.EntryPointStore) ServerOption {
	return func(s *Server) error {
		s.EpStore = r
		return nil
	}
}

// WithMiddlewareRegistry sets the middleware store.
func WithMiddlewareRegistry(r config.MiddlewareStore) ServerOption {
	return func(s *Server) error {
		s.MwStore = r
		return nil
	}
}

// WithTLSOptionRegistry sets the TLS option store.
func WithTLSOptionRegistry(r config.TLSOptionStore) ServerOption {
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

// WithAuthManager sets the auth manager. a may be nil: on a first run there is
// no global.json, so no Manager can be built until Setup has run.
//
// The manager is always wrapped in an auth.Holder so the value handed to the
// HTTP handlers is a stable reference rather than a snapshot. Setup swaps the
// real Manager in through Server.PublishAuthService; without the indirection
// the handlers would keep the startup nil for the life of the process and go
// on serving the management API unauthenticated after setup completed.
func WithAuthManager(a *auth.Manager) ServerOption {
	return func(s *Server) error {
		if a == nil {
			s.AuthManager = auth.NewHolder(nil)
			return nil
		}
		s.AuthManager = auth.NewHolder(a)
		return nil
	}
}

// WithEbpfManager sets the eBPF manager.
func WithEbpfManager(e ebpf.Manager) ServerOption {
	return func(s *Server) error {
		s.EbpfManager = e
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

// WithWafUpdater sets the WAF updater.
func WithWafUpdater(u any) ServerOption {
	return func(s *Server) error {
		s.WafUpdater = u
		return nil
	}
}

// WithClamAVManager sets the ClamAV manager.
func WithClamAVManager(m any) ServerOption {
	return func(s *Server) error {
		s.ClamAVManager = m
		return nil
	}
}

// WithWafRules sets the WAF rules store.
func WithWafRules(m any) ServerOption {
	return func(s *Server) error {
		s.WafRules = m
		return nil
	}
}

func WithIPReputation(r any) ServerOption {
	return func(s *Server) error {
		s.IPReputation = r
		return nil
	}
}

// WithPhantomCore sets the TITAN phantom core.
func WithPhantomCore(p phantom.PhantomCore) ServerOption {
	return func(s *Server) error {
		s.Phantom = p
		return nil
	}
}

// WithGovernor sets the resource governor.
func WithGovernor(g *resource.Governor) ServerOption {
	return func(s *Server) error {
		s.Governor = g
		return nil
	}
}

// WithLogger sets the logger.
func WithLogger(l logger.Logger) ServerOption {
	return func(s *Server) error {
		s.Logger = l
		return nil
	}
}
