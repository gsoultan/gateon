package server

import (
	"context"
	"crypto/tls"
	"strings"

	"github.com/gateon/gateon/internal/config"
	"github.com/gateon/gateon/internal/router"
	gtls "github.com/gateon/gateon/internal/tls"
)

// CreateTLSManager builds the TLS manager from global config.
func CreateTLSManager(globalStore config.GlobalConfigStore) *gtls.Manager {
	tlsManager := gtls.NewManager(gtls.InitFromEnv())
	gc := globalStore.Get(context.Background())
	if gc == nil || gc.Tls == nil || !gc.Tls.Enabled {
		return tlsManager
	}
	cfg := gtls.InitFromEnv()
	cfg.Enabled = true
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
	if gc.Tls.Acme != nil && gc.Tls.Acme.Enabled && gc.Tls.Acme.Email != "" {
		cfg.Email = gc.Tls.Acme.Email
	}
	if len(gc.Tls.Certificates) > 0 {
		for _, c := range gc.Tls.Certificates {
			cfg.Certificates = append(cfg.Certificates, gtls.CertificateConfig{
				ID: c.Id, Name: c.Name, CertFile: c.CertFile, KeyFile: c.KeyFile,
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
	return gtls.NewManager(cfg)
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
		if sniHost == "" {
			return nil, nil
		}
		// Strip port from SNI if present (RFC 6066 allows hostname only; some clients may send host:port)
		if idx := strings.LastIndex(sniHost, ":"); idx > 0 {
			sniHost = sniHost[:idx]
		}
		routes := deps.RouteStore.List(ctx)
		// First pass: exact host match (e.g. Host(`api.example.com`) for api.example.com)
		// Second pass: wildcard match (e.g. Host(`*.example.com`) for api.example.com)
		for _, exact := range []bool{true, false} {
			for _, rt := range routes {
				if rt.Disabled || rt.Tls == nil || len(rt.Tls.CertificateIds) == 0 {
					continue
				}
				routeHost := router.HostFromRule(rt.Rule)
				if routeHost == "" || !router.HostMatches(routeHost, sniHost) {
					continue
				}
				if router.RouteHostIsExact(routeHost) != exact {
					continue
				}
				var certs []tls.Certificate
				gc := deps.GlobalStore.Get(ctx)
				if gc == nil || gc.Tls == nil {
					continue
				}
				for _, certId := range rt.Tls.CertificateIds {
					for _, c := range gc.Tls.Certificates {
						if c.Id != certId {
							continue
						}
						cert, _, err := tlsManager.LoadCertificate(c.CertFile, c.KeyFile, "")
						if err == nil {
							certs = append(certs, *cert)
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
							newCfg.MinVersion = parseTLSVersion(opt.MinTlsVersion)
						}
						if opt.MaxTlsVersion != "" {
							newCfg.MaxVersion = parseTLSVersion(opt.MaxTlsVersion)
						}
						if len(opt.CipherSuites) > 0 && newCfg.MinVersion <= tls.VersionTLS12 {
							newCfg.CipherSuites = parseCipherSuites(opt.CipherSuites)
						}
						if opt.PreferServerCipherSuites {
							newCfg.PreferServerCipherSuites = true
						}
						if len(opt.AlpnProtocols) > 0 {
							newCfg.NextProtos = opt.AlpnProtocols
						}
					}
				}
				return newCfg, nil
			}
		}
		return nil, nil
	}
}

func parseTLSVersion(v string) uint16 {
	switch strings.ToUpper(v) {
	case "TLS12":
		return tls.VersionTLS12
	case "TLS13":
		return tls.VersionTLS13
	default:
		// TLS 1.0 and 1.1 are deprecated; treat unknown values as TLS 1.2
		return tls.VersionTLS12
	}
}

func parseCipherSuites(suites []string) []uint16 {
	var ids []uint16
	for _, s := range suites {
		for _, c := range tls.CipherSuites() {
			if c.Name == s {
				ids = append(ids, c.ID)
				break
			}
		}
	}
	return ids
}
