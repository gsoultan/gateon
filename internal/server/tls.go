package server

import (
	"crypto/tls"
	"strings"

	"github.com/gateon/gateon/internal/config"
	"github.com/gateon/gateon/internal/router"
	gtls "github.com/gateon/gateon/internal/tls"
)

// CreateTLSManager builds the TLS manager from global config.
func CreateTLSManager(globalReg *config.GlobalRegistry) *gtls.Manager {
	tlsManager := gtls.NewManager(gtls.InitFromEnv())
	gc := globalReg.Get()
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

// SetupSNI configures the TLS config for SNI-based certificate selection.
func SetupSNI(tlsConfig *tls.Config, tlsManager *gtls.Manager, s *Server) {
	if tlsConfig == nil {
		return
	}
	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		sniHost := strings.TrimSpace(hello.ServerName)
		if sniHost == "" {
			return nil, nil
		}
		for _, rt := range s.RouteReg.List() {
			if rt.Tls == nil || len(rt.Tls.CertificateIds) == 0 {
				continue
			}
			routeHost := router.HostFromRule(rt.Rule)
			if routeHost == "" || !router.HostMatches(routeHost, sniHost) {
				continue
			}
			var certs []tls.Certificate
			gc := s.GlobalReg.Get()
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
				if opt, ok := s.TLSOptReg.Get(rt.Tls.OptionId); ok {
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
		return nil, nil
	}
}

func parseTLSVersion(v string) uint16 {
	switch strings.ToUpper(v) {
	case "TLS10":
		return tls.VersionTLS10
	case "TLS11":
		return tls.VersionTLS11
	case "TLS12":
		return tls.VersionTLS12
	case "TLS13":
		return tls.VersionTLS13
	default:
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
