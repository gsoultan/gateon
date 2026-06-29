package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/router"
	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

var (
	certCache     sync.Map // string (certId) -> *tls.Certificate
	certPoolCache sync.Map // string (joined IDs) -> *x509.CertPool
)

// InvalidateTLSCache clears the certificate and pool caches.
// This is called when TLS configuration or certificates change.
func InvalidateTLSCache() {
	certCache.Clear()
	certPoolCache.Clear()
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
		// Calculate and store TLS fingerprints as early as possible
		f := middleware.CalcFingerprints(hello)
		middleware.SetFingerprints(hello.Conn, f)

		sniHost := strings.TrimSpace(hello.ServerName)
		if sniHost != "" {
			// Strip port from SNI if present (RFC 6066 allows hostname only; some clients may send host:port)
			if idx := strings.LastIndex(sniHost, ":"); idx > 0 {
				sniHost = sniHost[:idx]
			}
			sniHost = strings.ToLower(sniHost)

			// Fast-path: O(1) exact host lookup
			exactRoutes := deps.RouteStore.GetByHost(sniHost)

			// First pass: exact host match (e.g. Host(`api.example.com`) for api.example.com)
			// Second pass: wildcard match (e.g. Host(`*.example.com`) for api.example.com)
			for _, pass := range []struct {
				exact bool
				list  []*gateonv1.Route
			}{
				{true, exactRoutes},
				{false, deps.RouteStore.List(ctx)}, // Fallback to linear scan for wildcards
			} {
				for _, rt := range pass.list {
					if rt.Disabled || rt.Tls == nil || len(rt.Tls.CertificateIds) == 0 {
						continue
					}
					routeHost := router.HostFromRule(rt.Rule)
					if routeHost == "" || !router.HostMatches(routeHost, sniHost) {
						continue
					}
					isExactMatch := router.RouteHostIsExact(routeHost)
					if isExactMatch != pass.exact {
						continue
					}
					// If the route references a TLS option with SNI strict, do not allow wildcard matches
					if rt.Tls.OptionId != "" {
						if opt, ok := deps.TLSOptStore.Get(ctx, rt.Tls.OptionId); ok {
							if opt.SniStrict && !pass.exact {
								continue
							}
						}
					}

					var certs []tls.Certificate
					gc := deps.GlobalStore.Get(ctx)
					if gc == nil || gc.Tls == nil {
						continue
					}
					for _, certId := range rt.Tls.CertificateIds {
						// Cache check
						if cached, ok := certCache.Load(certId); ok {
							certs = append(certs, *cached.(*tls.Certificate))
							continue
						}

						for _, c := range gc.Tls.Certificates {
							if c.Id != certId {
								continue
							}
							cert, _, err := tlsManager.LoadCertificate(c.CertFile, c.KeyFile, c.CaFile)
							if err == nil {
								certs = append(certs, *cert)
								certCache.Store(certId, cert)
							} else {
								logger.L.Error().Err(err).
									Str("cert_id", c.Id).
									Str("cert_file", c.CertFile).
									Msg("Failed to load certificate for route")
							}
							break
						}
					}
					if len(certs) == 0 {
						continue
					}
					newCfg := tlsConfig.Clone()
					newCfg.Certificates = certs

					if rt.Tls.OptionId != "" {
						if opt, ok := deps.TLSOptStore.Get(ctx, rt.Tls.OptionId); ok {
							if opt.MinTlsVersion != "" {
								newCfg.MinVersion = gtls.ParseTLSVersion(opt.MinTlsVersion, tls.VersionTLS12)
							}
							if opt.MaxTlsVersion != "" {
								newCfg.MaxVersion = gtls.ParseTLSVersion(opt.MaxTlsVersion, 0)
							}
							if len(opt.CipherSuites) > 0 && newCfg.MinVersion <= tls.VersionTLS12 {
								newCfg.CipherSuites = gtls.ParseCipherSuites(opt.CipherSuites)
							}
							// PreferServerCipherSuites is deprecated and ignored by the Go runtime since Go 1.18.
							if len(opt.AlpnProtocols) > 0 {
								newCfg.NextProtos = opt.AlpnProtocols
							}
							if opt.ClientAuthType != "" {
								newCfg.ClientAuth = gtls.ParseClientAuthType(opt.ClientAuthType)
							}
							// Bind Client Authorities to tls.Config when present on TLS Option
							if len(opt.ClientAuthorityIds) > 0 {
								// Cache check for CertPool
								poolKey := "pool:" + strings.Join(opt.ClientAuthorityIds, ",")
								if cached, ok := certPoolCache.Load(poolKey); ok {
									newCfg.ClientCAs = cached.(*x509.CertPool)
								} else {
									// Build a CertPool from referenced Client Authorities in Global TLS config
									if gc := deps.GlobalStore.Get(ctx); gc != nil && gc.Tls != nil {
										var pool *x509.CertPool
										for _, wantID := range opt.ClientAuthorityIds {
											for _, ca := range gc.Tls.ClientAuthorities {
												if ca.Id != wantID {
													continue
												}
												if pool == nil {
													pool = x509.NewCertPool()
												}
												// Read PEM file and append certs; errors ignored here to avoid handshake crash
												// The manager-level validation will surface issues via API/logs.
												if caData, err := tlsManager.LoadCAData(ca.CaFile); err == nil && caData != nil {
													pool.AppendCertsFromPEM(caData)
												}
												break
											}
										}
										if pool != nil {
											newCfg.ClientCAs = pool
											certPoolCache.Store(poolKey, pool)
										}
									}
								}
							}
						}
					}
					return newCfg, nil
				}
			}
		}

		// Fallback: use global TLS config (dynamic certificates)
		gc := deps.GlobalStore.Get(ctx)
		if gc != nil && gc.Tls != nil && len(gc.Tls.Certificates) > 0 {
			var certs []tls.Certificate
			for _, c := range gc.Tls.Certificates {
				cert, _, err := tlsManager.LoadCertificate(c.CertFile, c.KeyFile, c.CaFile)
				if err == nil {
					certs = append(certs, *cert)
				} else {
					logger.L.Error().Err(err).
						Str("cert_id", c.Id).
						Str("cert_file", c.CertFile).
						Msg("Failed to load global certificate")
				}
			}
			if len(certs) > 0 {
				newCfg := tlsConfig.Clone()
				newCfg.Certificates = certs
				if gc.Tls.MinTlsVersion != "" {
					newCfg.MinVersion = gtls.ParseTLSVersion(gc.Tls.MinTlsVersion, tls.VersionTLS12)
				}
				if gc.Tls.MaxTlsVersion != "" {
					newCfg.MaxVersion = gtls.ParseTLSVersion(gc.Tls.MaxTlsVersion, 0)
				}
				if gc.Tls.ClientAuthType != "" {
					newCfg.ClientAuth = gtls.ParseClientAuthType(gc.Tls.ClientAuthType)
				}
				if len(gc.Tls.ClientAuthorities) > 0 {
					ids := make([]string, 0, len(gc.Tls.ClientAuthorities))
					for _, ca := range gc.Tls.ClientAuthorities {
						ids = append(ids, ca.Id)
					}
					poolKey := "global-pool:" + strings.Join(ids, ",")
					if cached, ok := certPoolCache.Load(poolKey); ok {
						newCfg.ClientCAs = cached.(*x509.CertPool)
					} else {
						var pool *x509.CertPool
						for _, ca := range gc.Tls.ClientAuthorities {
							if caData, err := tlsManager.LoadCAData(ca.CaFile); err == nil && caData != nil {
								if pool == nil {
									pool = x509.NewCertPool()
								}
								pool.AppendCertsFromPEM(caData)
							}
						}
						if pool != nil {
							newCfg.ClientCAs = pool
							certPoolCache.Store(poolKey, pool)
						}
					}
				}

				return newCfg, nil
			}
		}

		return nil, nil
	}
}
