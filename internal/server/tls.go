// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/router"
	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

var (
	certCache      sync.Map // string (certId) -> *tls.Certificate
	certPoolCache  sync.Map // string (joined IDs) -> *x509.CertPool
	tlsConfigCache sync.Map // string (routeId or "fallback") -> *tls.Config
)

// InvalidateTLSCache clears the certificate and pool caches.
// This is called when TLS configuration or certificates change.
func InvalidateTLSCache() {
	certCache.Clear()
	certPoolCache.Clear()
	tlsConfigCache.Clear()
}

// CreateTLSManager builds the TLS manager from global config.
func CreateTLSManager(s *Server) *gtls.Manager {
	gc := s.GlobalStore.Get(context.Background())
	cfg := BuildGtlsConfig(s)
	m := gtls.NewManager(cfg)

	// Set dynamic host policy for ACME
	m.SetHostPolicy(func(ctx context.Context, host string) error {
		// Check global whitelist first
		for _, d := range cfg.Domains {
			if host == d {
				return nil
			}
		}
		// Check routes for ACME enablement
		routes := s.RouteStore.List(ctx)
		for _, rt := range routes {
			if rt.Disabled || rt.Tls == nil || !rt.Tls.AcmeEnabled {
				continue
			}
			routeHost := router.HostFromRule(rt.Rule)
			if routeHost != "" && router.HostMatches(routeHost, host) {
				return nil
			}
		}
		return fmt.Errorf("host %q not authorized for ACME", host)
	})

	// Set persistent cache
	if s.RedisClient != nil {
		m.SetCache(gtls.NewRedisCache(s.RedisClient, "gateon:acme:"))
	} else if gc != nil && gc.Auth != nil {
		// Try to use the same DB as auth for ACME cache if it's SQL
		// This is a bit complex to get the *sql.DB here, but we can try.
		// For now, default to DirCache (implemented in gtls.Manager)
	}

	return m
}

// BuildGtlsConfig builds a gtls.Config from the current server state.
func BuildGtlsConfig(s *Server) gtls.Config {
	gc := s.GlobalStore.Get(context.Background())
	cfg := gtls.InitFromEnv()

	if gc != nil && gc.Tls != nil {
		if gc.Tls.Enabled {
			cfg.Enabled = true
		}
		if gc.Tls.Email != "" {
			cfg.Email = gc.Tls.Email
		}
		if len(gc.Tls.Domains) > 0 {
			cfg.Domains = gc.Tls.Domains
		}
		if gc.Tls.MinTlsVersion != "" {
			cfg.MinVersion = gc.Tls.MinTlsVersion
		}
		if gc.Tls.MaxTlsVersion != "" {
			cfg.MaxVersion = gc.Tls.MaxTlsVersion
		}
		if gc.Tls.ClientAuthType != "" {
			cfg.ClientAuthType = gc.Tls.ClientAuthType
		}
		if len(gc.Tls.CipherSuites) > 0 {
			cfg.CipherSuites = gc.Tls.CipherSuites
		}
		if gc.Tls.Acme != nil && gc.Tls.Acme.Enabled {
			cfg.Acme = gtls.AcmeConfig{
				Enabled:  true,
				Email:    gc.Tls.Acme.Email,
				CAServer: gc.Tls.Acme.CaServer,
			}
			if cfg.Acme.Email == "" {
				cfg.Acme.Email = gc.Tls.Email
			}
		}
		if len(gc.Tls.Certificates) > 0 {
			for _, c := range gc.Tls.Certificates {
				cfg.Certificates = append(cfg.Certificates, gtls.CertificateConfig{
					ID: c.Id, Name: c.Name, CertFile: c.CertFile, KeyFile: c.KeyFile, CaFile: c.CaFile,
				})
			}
		}
		if len(gc.Tls.ClientAuthorities) > 0 {
			for _, ca := range gc.Tls.ClientAuthorities {
				cfg.ClientAuthorities = append(cfg.ClientAuthorities, gtls.ClientAuthorityConfig{
					ID: ca.Id, Name: ca.Name, CaFile: ca.CaFile,
				})
			}
		}
	}
	return cfg
}

// SNIDeps holds narrow dependencies for SetupSNI (Interface Segregation).
type SNIDeps struct {
	RouteStore  config.RouteStore
	GlobalStore config.GlobalConfigStore
	TLSOptStore config.TLSOptionStore
}

// SetupSNI configures the TLS config for SNI-based certificate selection.
// For multi-domain setups, SNI selects the certificate by matching the client's
// ServerName (host) against route rules. Exact host matches (e.g. api.example.com)
// are preferred over wildcard matches (e.g. *.example.com). Disabled routes are ignored.
func SetupSNI(tlsConfig *tls.Config, tlsManager gtls.TLSManager, deps SNIDeps) {
	if tlsConfig == nil {
		return
	}
	ctx := context.Background()
	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		sniHost := strings.TrimSpace(hello.ServerName)
		var fingerprints *middleware.Fingerprints // lazy-calc fingerprints

		getFp := func() middleware.Fingerprints {
			if fingerprints == nil {
				f := middleware.CalcFingerprints(hello)
				fingerprints = &f
			}
			return *fingerprints
		}

		if sniHost != "" {
			// Strip port from SNI if present
			if idx := strings.LastIndex(sniHost, ":"); idx > 0 {
				sniHost = sniHost[:idx]
			}
			sniHost = strings.ToLower(sniHost)

			// Fast-path: O(1) exact host lookup
			exactRoutes := deps.RouteStore.GetByHost(sniHost)
			for _, rt := range exactRoutes {
				if rt.Disabled || rt.Tls == nil {
					continue
				}

				if cached, ok := tlsConfigCache.Load(rt.Id); ok {
					middleware.SetFingerprints(hello.Conn, getFp())
					return cached.(*tls.Config), nil
				}

				if newCfg := buildTLSConfigForRoute(hello, rt, tlsConfig, tlsManager, deps, getFp); newCfg != nil {
					tlsConfigCache.Store(rt.Id, newCfg)
					return newCfg, nil
				}
			}

			for _, rt := range deps.RouteStore.ListWildcards(ctx) {
				if rt.Disabled || rt.Tls == nil {
					continue
				}
				routeHost := router.HostFromRule(rt.Rule)
				if routeHost == "" || !router.HostMatches(routeHost, sniHost) {
					continue
				}
				if rt.Tls.OptionId != "" {
					if opt, ok := deps.TLSOptStore.Get(ctx, rt.Tls.OptionId); ok && opt.SniStrict {
						continue
					}
				}
				if cached, ok := tlsConfigCache.Load(rt.Id); ok {
					middleware.SetFingerprints(hello.Conn, getFp())
					return cached.(*tls.Config), nil
				}
				if newCfg := buildTLSConfigForRoute(hello, rt, tlsConfig, tlsManager, deps, getFp); newCfg != nil {
					tlsConfigCache.Store(rt.Id, newCfg)
					return newCfg, nil
				}
			}
		}

		// Fallback: use global TLS config
		gc := deps.GlobalStore.Get(context.Background())
		if gc != nil && gc.Tls != nil {
			if cached, ok := tlsConfigCache.Load("fallback"); ok {
				middleware.SetFingerprints(hello.Conn, getFp())
				return cached.(*tls.Config), nil
			}

			if newCfg := buildFallbackTLSConfig(hello, gc, tlsConfig, tlsManager, getFp); newCfg != nil {
				tlsConfigCache.Store("fallback", newCfg)
				return newCfg, nil
			}
		}
		return nil, nil
	}
}

func buildTLSConfigForRoute(hello *tls.ClientHelloInfo, rt *gateonv1.Route, base *tls.Config, manager gtls.TLSManager, deps SNIDeps, getFp func() middleware.Fingerprints) *tls.Config {
	ctx := context.Background()
	var certs []tls.Certificate

	// Handle ACME if enabled for this route
	if rt.Tls.AcmeEnabled && len(rt.Tls.CertificateIds) == 0 {
		cfg := base.Clone()
		cfg.GetCertificate = manager.GetCertificate
		middleware.SetFingerprints(hello.Conn, getFp())
		return cfg
	}

	for _, id := range rt.Tls.CertificateIds {
		if cached, ok := certCache.Load(id); ok {
			certs = append(certs, *cached.(*tls.Certificate))
		} else if c, ok := deps.GlobalStore.GetCertificate(id); ok {
			if cert, _, err := manager.LoadCertificate(c.CertFile, c.KeyFile, c.CaFile); err == nil {
				certs = append(certs, *cert)
				certCache.Store(id, cert)
			}
		}
	}
	if len(certs) == 0 {
		return nil
	}

	cfg := base.Clone()
	cfg.Certificates = certs
	middleware.SetFingerprints(hello.Conn, getFp())

	if rt.Tls.OptionId != "" {
		if opt, ok := deps.TLSOptStore.Get(ctx, rt.Tls.OptionId); ok {
			if opt.MinTlsVersion != "" {
				cfg.MinVersion = gtls.ParseTLSVersion(opt.MinTlsVersion, tls.VersionTLS12)
			}
			if opt.MaxTlsVersion != "" {
				cfg.MaxVersion = gtls.ParseTLSVersion(opt.MaxTlsVersion, 0)
			}
			if len(opt.CipherSuites) > 0 && cfg.MinVersion <= tls.VersionTLS12 {
				cfg.CipherSuites = gtls.ParseCipherSuites(opt.CipherSuites)
			}
			if len(opt.AlpnProtocols) > 0 {
				cfg.NextProtos = opt.AlpnProtocols
			}
			if opt.ClientAuthType != "" {
				cfg.ClientAuth = gtls.ParseClientAuthType(opt.ClientAuthType)
			}
			if len(opt.ClientAuthorityIds) > 0 {
				poolKey := "pool:" + strings.Join(opt.ClientAuthorityIds, ",")
				if cached, ok := certPoolCache.Load(poolKey); ok {
					cfg.ClientCAs = cached.(*x509.CertPool)
				} else if gc := deps.GlobalStore.Get(ctx); gc != nil && gc.Tls != nil {
					var pool *x509.CertPool
					for _, wantID := range opt.ClientAuthorityIds {
						for _, ca := range gc.Tls.ClientAuthorities {
							if ca.Id == wantID {
								if data, err := manager.LoadCAData(ca.CaFile); err == nil && data != nil {
									if pool == nil {
										pool = x509.NewCertPool()
									}
									pool.AppendCertsFromPEM(data)
								}
								break
							}
						}
					}
					if pool != nil {
						cfg.ClientCAs = pool
						certPoolCache.Store(poolKey, pool)
					}
				}
			}
		}
	}
	return cfg
}

func buildFallbackTLSConfig(hello *tls.ClientHelloInfo, gc *gateonv1.GlobalConfig, base *tls.Config, manager gtls.TLSManager, getFp func() middleware.Fingerprints) *tls.Config {
	// Handle global ACME if enabled and no manual certificates are provided
	if gc.Tls.Acme != nil && gc.Tls.Acme.Enabled && len(gc.Tls.Certificates) == 0 {
		cfg := base.Clone()
		cfg.GetCertificate = manager.GetCertificate
		middleware.SetFingerprints(hello.Conn, getFp())
		return cfg
	}

	var certs []tls.Certificate
	for _, c := range gc.Tls.Certificates {
		if cached, ok := certCache.Load(c.Id); ok {
			certs = append(certs, *cached.(*tls.Certificate))
		} else if cert, _, err := manager.LoadCertificate(c.CertFile, c.KeyFile, c.CaFile); err == nil {
			certs = append(certs, *cert)
			certCache.Store(c.Id, cert)
		}
	}
	if len(certs) == 0 {
		return nil
	}
	cfg := base.Clone()
	cfg.Certificates = certs
	middleware.SetFingerprints(hello.Conn, getFp())
	return cfg
}
