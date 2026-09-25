// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

	"golang.org/x/crypto/acme"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/security/identity"
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

// InvalidateRouteTLSConfig drops the cached per-route tls.Config so the next
// handshake for that route rebuilds it from the current route, option and
// certificate state. Route edits reach the server through
// Invalidator.InvalidateRoute, which did not touch this cache, so a route
// switched to mTLS kept serving the config it was first seen with.
func InvalidateRouteTLSConfig(routeID string) {
	tlsConfigCache.Delete(routeID)
}

// CreateTLSManager builds the TLS manager from global config.
func CreateTLSManager(s *Server) *gtls.Manager {
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

	// Set persistent cache. Without Redis the manager falls back to its own
	// DirCache; reusing the auth database for the ACME cache would need the
	// *sql.DB threaded down to here, which it is not, so the fallback stands
	// rather than being half-wired. The empty else-if that used to record that
	// evaluated a condition and did nothing with it.
	if s.RedisClient != nil {
		m.SetCache(gtls.NewRedisCache(s.RedisClient, "gateon:acme:"))
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
				Enabled:       true,
				Email:         gc.Tls.Acme.Email,
				CAServer:      gc.Tls.Acme.CaServer,
				ChallengeType: acmeChallengeType(gc.Tls.Acme.ChallengeType),
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
	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		// Per-handshake, not a Background hoisted out of the closure. These
		// store reads happen while a client is waiting on a TLS handshake; if
		// that client goes away, the lookups should stop with it rather than
		// run on behalf of a connection that no longer exists. hello.Context()
		// is cancelled when the handshake concludes either way.
		ctx := hello.Context()
		var fingerprints *identity.Fingerprints // lazy-calc fingerprints

		getFp := func() identity.Fingerprints {
			if fingerprints == nil {
				f := identity.CalcFingerprints(hello)
				fingerprints = &f
			}
			return *fingerprints
		}

		// Exact-host routes first (O(1) lookup), then wildcards; the first
		// route whose configuration is cached or builds is the one served.
		var selected *tls.Config
		deps.eachRouteForSNI(ctx, normalizeSNI(hello.ServerName), func(rt *gateonv1.Route) bool {
			if cached, ok := tlsConfigCache.Load(rt.Id); ok {
				identity.SetFingerprints(hello.Conn, getFp())
				selected = cached.(*tls.Config)
				return false
			}
			if newCfg := buildTLSConfigForRoute(hello, rt, tlsConfig, tlsManager, deps, getFp); newCfg != nil {
				tlsConfigCache.Store(rt.Id, newCfg)
				selected = newCfg
				return false
			}
			return true
		})
		if selected != nil {
			return selected, nil
		}

		// Fallback: use global TLS config
		gc := deps.GlobalStore.Get(ctx)
		if gc != nil && gc.Tls != nil {
			if cached, ok := tlsConfigCache.Load("fallback"); ok {
				identity.SetFingerprints(hello.Conn, getFp())
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

// normalizeSNI puts a handshake's server name into the spelling routes are
// looked up by: trimmed, port removed, lower-cased.
func normalizeSNI(serverName string) string {
	sniHost := strings.TrimSpace(serverName)
	if idx := strings.LastIndex(sniHost, ":"); idx > 0 {
		sniHost = sniHost[:idx]
	}
	return strings.ToLower(sniHost)
}

// eachRouteForSNI visits, in the order a handshake tries them, the routes
// whose TLS configuration a handshake naming sniHost may be served under:
// enabled TLS routes for exactly that host, then wildcard TLS routes covering
// it whose option is not sni_strict. visit returns false to stop.
//
// It is the one enumeration both the handshake and routeTLSPolicyHonoured use,
// so the name a request is checked against cannot drift from the name its
// connection was negotiated under.
func (d SNIDeps) eachRouteForSNI(ctx context.Context, sniHost string, visit func(*gateonv1.Route) bool) {
	if sniHost == "" {
		return
	}
	for _, rt := range d.RouteStore.GetByHost(sniHost) {
		if rt.Disabled || rt.Tls == nil {
			continue
		}
		if !visit(rt) {
			return
		}
	}
	for _, rt := range d.RouteStore.ListWildcards(ctx) {
		if d.wildcardServesSNI(ctx, rt, sniHost) && !visit(rt) {
			return
		}
	}
}

// wildcardServesSNI reports whether wildcard route rt may serve a handshake
// naming sniHost: enabled, with TLS, a host pattern covering sniHost, and no
// sni_strict option.
func (d SNIDeps) wildcardServesSNI(ctx context.Context, rt *gateonv1.Route, sniHost string) bool {
	if rt.Disabled || rt.Tls == nil {
		return false
	}
	routeHost := router.HostFromRule(rt.Rule)
	if routeHost == "" || !router.HostMatches(routeHost, sniHost) {
		return false
	}
	if rt.Tls.OptionId != "" && d.TLSOptStore != nil {
		if opt, ok := d.TLSOptStore.Get(ctx, rt.Tls.OptionId); ok && opt.SniStrict {
			return false
		}
	}
	return true
}

// routeTLSPolicyHonoured reports whether the TLS handshake that carried r was
// negotiated under rt's TLS option.
//
// A route's option -- above all its client-certificate requirement -- is
// enforced during the handshake, and the handshake chooses its configuration
// from the SNI name before any HTTP is read. The route that serves the request
// is chosen afterwards, from the Host header. The client writes both, so a
// client could complete the handshake under a route that asks for no
// certificate and then name an mTLS route in Host: domain fronting, and the
// route's requirement was never applied to the request it served.
//
// Two checks, skipped entirely for a route without an option. The SNI name
// must select a route carrying the same option: the policy the handshake ran
// is the policy this route asked for. And a route whose option requires a
// client certificate must find one on the connection, which also covers a
// handshake that fell through to another route's configuration because this
// route's own certificate could not be loaded.
func (d SNIDeps) routeTLSPolicyHonoured(r *http.Request, rt *gateonv1.Route) bool {
	optID := rt.GetTls().GetOptionId()
	if optID == "" || r.TLS == nil {
		return true
	}
	var sniRoute *gateonv1.Route
	d.eachRouteForSNI(r.Context(), normalizeSNI(r.TLS.ServerName), func(first *gateonv1.Route) bool {
		sniRoute = first
		return false
	})
	if sniRoute.GetTls().GetOptionId() != optID {
		return false
	}
	if d.TLSOptStore == nil {
		return true
	}
	opt, ok := d.TLSOptStore.Get(r.Context(), optID)
	if !ok {
		return true
	}
	return clientCertRequirementMet(gtls.ParseClientAuthType(opt.ClientAuthType), r.TLS)
}

// clientCertRequirementMet reports whether a connection carries the client
// certificate a client-auth mode demands. Modes that do not demand one are met
// by any connection.
func clientCertRequirementMet(mode tls.ClientAuthType, cs *tls.ConnectionState) bool {
	switch mode {
	case tls.RequireAndVerifyClientCert:
		return len(cs.VerifiedChains) > 0
	case tls.RequireAnyClientCert:
		return len(cs.PeerCertificates) > 0
	default:
		return true
	}
}

func buildTLSConfigForRoute(hello *tls.ClientHelloInfo, rt *gateonv1.Route, base *tls.Config, manager gtls.TLSManager, deps SNIDeps, getFp func() identity.Fingerprints) *tls.Config {
	// Same reasoning as SetupSNI: this runs inside the handshake, so the TLS
	// option lookup below belongs to the connection being negotiated.
	ctx := hello.Context()

	// Where the certificate comes from is the only thing ACME changes. The
	// ACME branch used to return here, before the route's TLS option was
	// applied, so an ACME route configured for mTLS asked no client for a
	// certificate and ignored the option's version and cipher floor too.
	var cfg *tls.Config
	if rt.Tls.AcmeEnabled && len(rt.Tls.CertificateIds) == 0 {
		cfg = base.Clone()
		cfg.GetCertificate = manager.GetCertificate
	} else {
		certs := routeCertificates(rt, manager, deps)
		if len(certs) == 0 {
			return nil
		}
		cfg = base.Clone()
		cfg.Certificates = certs
	}
	identity.SetFingerprints(hello.Conn, getFp())

	if rt.Tls.OptionId != "" {
		if opt, ok := deps.TLSOptStore.Get(ctx, rt.Tls.OptionId); ok {
			applyTLSOption(cfg, opt, ctx, manager, deps)
		}
	}
	if rt.Tls.AcmeEnabled && !slices.Contains(cfg.NextProtos, acme.ALPNProto) {
		// An option's own ALPN list replaces the base one; an ACME route still
		// has to answer the CA's TLS-ALPN-01 validation on acme-tls/1.
		cfg.NextProtos = append(slices.Clone(cfg.NextProtos), acme.ALPNProto)
	}
	failClosedClientCAs(cfg, rt.Id)
	return cfg
}

// routeCertificates resolves a route's configured certificates, preferring the
// process cache so a handshake does not re-read them from disk.
func routeCertificates(rt *gateonv1.Route, manager gtls.TLSManager, deps SNIDeps) []tls.Certificate {
	var certs []tls.Certificate
	for _, id := range rt.Tls.CertificateIds {
		if cached, ok := certCache.Load(id); ok {
			if cert, ok := cached.(*tls.Certificate); ok {
				certs = append(certs, *cert)
			}
			continue
		}
		c, ok := deps.GlobalStore.GetCertificate(id)
		if !ok {
			continue
		}
		if cert, _, err := manager.LoadCertificate(c.CertFile, c.KeyFile, c.CaFile); err == nil {
			certs = append(certs, *cert)
			certCache.Store(id, cert)
		}
	}
	return certs
}

// applyTLSOption overlays a route's named TLS option onto its config. Each
// field is applied only when set, so an option that names a minimum version
// and nothing else does not silently reset the cipher list or the ALPN set.
func applyTLSOption(cfg *tls.Config, opt *gateonv1.TLSOption, ctx context.Context, manager gtls.TLSManager, deps SNIDeps) {
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
		applyClientAuthorities(cfg, opt.ClientAuthorityIds, ctx, manager, deps)
	}
}

// applyClientAuthorities builds the client-CA pool for an mTLS route. Leaving
// ClientCAs nil when the configured authority cannot be loaded is what
// failClosedClientCAs exists to catch, so this sets the pool only when it
// actually has one.
func applyClientAuthorities(cfg *tls.Config, authorityIDs []string, ctx context.Context, manager gtls.TLSManager, deps SNIDeps) {
	poolKey := "pool:" + strings.Join(authorityIDs, ",")
	if cached, ok := certPoolCache.Load(poolKey); ok {
		if pool, ok := cached.(*x509.CertPool); ok {
			cfg.ClientCAs = pool
		}
		return
	}

	gc := deps.GlobalStore.Get(ctx)
	if gc == nil || gc.Tls == nil {
		return
	}

	var pool *x509.CertPool
	for _, wantID := range authorityIDs {
		for _, ca := range gc.Tls.ClientAuthorities {
			if ca.Id != wantID {
				continue
			}
			if data, err := manager.LoadCAData(ca.CaFile); err == nil && data != nil {
				if pool == nil {
					pool = x509.NewCertPool()
				}
				pool.AppendCertsFromPEM(data)
			}
			break
		}
	}

	if pool != nil {
		cfg.ClientCAs = pool
		certPoolCache.Store(poolKey, pool)
	}
}

// failClosedClientCAs closes the gap crypto/tls leaves when a verifying
// ClientAuth is paired with a nil ClientCAs: x509 then verifies the client's
// chain against the system roots, so a route that asked for mTLS against its
// own authority would accept any certificate a public CA has issued. An empty
// pool verifies nothing, which is the only correct answer when the configured
// authority could not be loaded.
func failClosedClientCAs(cfg *tls.Config, routeID string) {
	// Named rather than compared ordinally: these are exactly the two modes in
	// which crypto/tls verifies a presented chain.
	switch cfg.ClientAuth {
	case tls.VerifyClientCertIfGiven, tls.RequireAndVerifyClientCert:
	default:
		return
	}
	if cfg.ClientCAs != nil {
		return
	}
	logger.L.LogError("client certificate verification requested but no client authority could be loaded; "+
		"rejecting every client certificate rather than falling back to the system roots",
		"route", routeID, "client_auth", cfg.ClientAuth.String())
	cfg.ClientCAs = x509.NewCertPool()
}

func buildFallbackTLSConfig(hello *tls.ClientHelloInfo, gc *gateonv1.GlobalConfig, base *tls.Config, manager gtls.TLSManager, getFp func() identity.Fingerprints) *tls.Config {
	// Handle global ACME if enabled and no manual certificates are provided
	if gc.Tls.Acme != nil && gc.Tls.Acme.Enabled && len(gc.Tls.Certificates) == 0 {
		cfg := base.Clone()
		cfg.GetCertificate = manager.GetCertificate
		identity.SetFingerprints(hello.Conn, getFp())
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
	identity.SetFingerprints(hello.Conn, getFp())
	return cfg
}

// acmeChallengeType validates the configured ACME challenge.
//
// The field was previously dropped on the way into the TLS manager, which took
// its value from GATEON_ACME_CHALLENGE_TYPE alone, so setting it in the
// dashboard did nothing.
//
// "dns" is rejected rather than passed through. The proto used to list it, but
// ACME here is autocert, which implements HTTP-01 and TLS-ALPN-01 only —
// forwarding it would leave the manager with a challenge it cannot run, and the
// operator would see certificate issuance fail with no explanation. Returning
// empty falls back to the default challenge, which is what happened before.
func acmeChallengeType(configured string) string {
	switch strings.ToLower(strings.TrimSpace(configured)) {
	case "http", "tls-alpn":
		return strings.ToLower(strings.TrimSpace(configured))
	case "":
		return ""
	case "dns":
		logger.L.LogError("acme.challenge_type \"dns\" is not supported: this build uses autocert, "+
			"which implements HTTP-01 and TLS-ALPN-01 only. Falling back to the default challenge. "+
			"Wildcard certificates require DNS-01 and are not available.",
			"configured", configured)
		return ""
	default:
		logger.L.LogWarn("unknown acme.challenge_type; falling back to the default",
			"configured", configured, "supported", "http, tls-alpn")
		return ""
	}
}
