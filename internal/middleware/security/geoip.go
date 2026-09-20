// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/pkg/httputil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/oschwald/geoip2-golang"
)

// GeoIPConfig configures the GeoIP allow/deny middleware.
type GeoIPConfig struct {
	DBPath          string   // Path to GeoLite2-Country.mmdb (required)
	AllowCountries  []string // ISO 3166-1 alpha-2 codes, e.g. US, GB
	DenyCountries   []string // ISO 3166-1 alpha-2 codes
	TrustCloudflare bool     // Use CF-Connecting-IP for client IP
}

// GeoIP returns a middleware that allows or denies requests by country using MaxMind GeoIP2/GeoLite2.
func GeoIP(cfg GeoIPConfig) (kind.Middleware, error) {
	if cfg.DBPath == "" {
		cfg.DBPath = os.Getenv("GATEON_GEOIP_DB_PATH")
	}
	if cfg.DBPath == "" {
		return nil, fmt.Errorf("geoip requires db_path or GATEON_GEOIP_DB_PATH env")
	}

	db, err := geoip2.Open(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("geoip open db: %w", err)
	}

	allowSet := make(map[string]bool)
	for _, c := range cfg.AllowCountries {
		allowSet[strings.ToUpper(strings.TrimSpace(c))] = true
	}
	denySet := make(map[string]bool)
	for _, c := range cfg.DenyCountries {
		denySet[strings.ToUpper(strings.TrimSpace(c))] = true
	}

	rt := geoIPRuntime{db: db, allow: allowSet, deny: denySet, trust: cfg.TrustCloudflare}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rt.serve(next, w, r)
		})
	}, nil
}

// geoIPRuntime is the per-route geofencing policy, resolved once: the opened
// database and the two country sets, already upper-cased.
type geoIPRuntime struct {
	db    *geoip2.Reader
	allow map[string]bool
	deny  map[string]bool
	trust bool
}

func (g geoIPRuntime) serve(next http.Handler, w http.ResponseWriter, r *http.Request) {
	if kind.IsCorsPreflight(r) || kind.ShouldSkipMetrics(r) {
		next.ServeHTTP(w, r)
		return
	}

	clientIP := request.GetClientIP(r, g.trust)
	ip := net.ParseIP(clientIP)
	if ip == nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		logger.L.LogDebug("geoip: invalid client IP", "ip", clientIP)
		return
	}

	record, err := g.db.Country(ip)
	if err != nil {
		// Unknown IP or lookup error: allow by default to avoid blocking
		next.ServeHTTP(w, r)
		return
	}

	country := strings.ToUpper(record.Country.IsoCode)
	if country == "" {
		country = "XX"
	}

	// Add country to context for other middlewares to use
	r = r.WithContext(request.WithCountry(r.Context(), country))
	if sw, ok := w.(*httputil.StatusResponseWriter); ok {
		sw.Country = country
	}

	switch {
	case g.deny[country]:
		g.refuse(w, r, clientIP, country, "Request from denied country: "+country,
			"geoip: request denied by country")
	case len(g.allow) > 0 && !g.allow[country]:
		g.refuse(w, r, clientIP, country, "Request from country not in allow list: "+country,
			"geoip: request not in allow list")
	default:
		next.ServeHTTP(w, r)
	}
}

// refuse records the geofencing decision and answers 403. The client is told
// only "Forbidden": naming the country would confirm which geofence it hit.
func (g geoIPRuntime) refuse(w http.ResponseWriter, r *http.Request, clientIP, country, details, logMsg string) {
	telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
		Type:        "geoip_block",
		SourceIP:    clientIP,
		Score:       50,
		Details:     details,
		Time:        time.Now(),
		RouteID:     kind.GetRouteName(r),
		RequestURI:  r.URL.RequestURI(),
		Category:    "geofencing",
		Severity:    kind.SeverityMedium,
		ActionTaken: kind.ActionBlocked,
	}))
	http.Error(w, "Forbidden", http.StatusForbidden)
	logger.L.LogDebug(logMsg, "ip", clientIP, "country", country)
}

// GeoIPGlobal returns a middleware that blocks or allows requests globally based on the country.
func GeoIPGlobal(ctx context.Context, globalStore config.GlobalConfigStore) kind.Middleware {
	return GeoIPGlobalWithResolver(ctx, globalStore, telemetry.ResolveCountry)
}

type geoIPGlobalState struct {
	blocked map[string]struct{}
	allowed map[string]struct{}
	mu      sync.RWMutex
}

func (s *geoIPGlobalState) update(newCfg *gateonv1.GlobalConfig) {
	if newCfg == nil || newCfg.Geoip == nil {
		return
	}
	blocked := make(map[string]struct{}, len(newCfg.Geoip.BlockedCountries))
	for _, c := range newCfg.Geoip.BlockedCountries {
		blocked[strings.ToUpper(c)] = struct{}{}
	}
	allowed := make(map[string]struct{}, len(newCfg.Geoip.AllowedCountries))
	for _, c := range newCfg.Geoip.AllowedCountries {
		allowed[strings.ToUpper(c)] = struct{}{}
	}
	s.mu.Lock()
	s.blocked = blocked
	s.allowed = allowed
	s.mu.Unlock()
}

// GeoIPGlobalWithResolver is the internal implementation of GeoIPGlobal, allowing for dependency injection in tests.
// GeoIPGlobalWithResolver takes a context for the initial config load only.
// The middleware it returns reads the store through each request's own
// context; ctx belongs to whoever is building the chain, so a shutdown during
// startup cancels the load rather than outliving it.
func GeoIPGlobalWithResolver(ctx context.Context, globalStore config.GlobalConfigStore, resolver func(string) string) kind.Middleware {
	state := &geoIPGlobalState{}
	// Initial load
	state.update(globalStore.Get(ctx))

	// Subscribe to changes
	if sub, ok := globalStore.(interface {
		Subscribe(config.ConfigChangeFunc)
	}); ok {
		sub.Subscribe(func(_, newCfg *gateonv1.GlobalConfig) {
			state.update(newCfg)
		})
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serveGlobalGeoIP(state, globalStore, resolver, next, w, r)
		})
	}
}

func serveGlobalGeoIP(state *geoIPGlobalState, globalStore config.GlobalConfigStore,
	resolver func(string) string, next http.Handler, w http.ResponseWriter, r *http.Request,
) {
	gc := globalStore.Get(r.Context())
	if gc == nil || gc.Geoip == nil || !gc.Geoip.Enabled ||
		kind.IsCorsPreflight(r) || kind.ShouldSkipMetrics(r) {
		next.ServeHTTP(w, r)
		return
	}

	clientIP := request.GetClientIP(r, config.EffectiveTrustCloudflare())
	country := resolver(clientIP)

	// Add country to context for other middlewares to use
	r = r.WithContext(request.WithCountry(r.Context(), country))
	if sw, ok := w.(*httputil.StatusResponseWriter); ok {
		sw.Country = country
	}

	state.mu.RLock()
	_, blocked := state.blocked[country]
	hasAllowed := len(state.allowed) > 0
	_, allowed := state.allowed[country]
	state.mu.RUnlock()

	switch {
	case blocked:
		recordGlobalBlock(r, clientIP, country, "denied by global blocklist")
		http.Error(w, "Forbidden", http.StatusForbidden)
	case hasAllowed && !allowed:
		recordGlobalBlock(r, clientIP, country, "not in global allowlist")
		http.Error(w, "Forbidden", http.StatusForbidden)
	default:
		next.ServeHTTP(w, r)
	}
}

func recordGlobalBlock(r *http.Request, clientIP, country, reason string) {

	telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
		Type:        "geoip_block",
		SourceIP:    clientIP,
		Score:       50,
		Details:     fmt.Sprintf("Global Block: %s (Country: %s)", reason, country),
		Time:        time.Now(),
		RouteID:     "global",
		RequestURI:  r.URL.RequestURI(),
		Category:    "geofencing",
		Severity:    kind.SeverityMedium,
		ActionTaken: kind.ActionBlocked,
	}))
	logger.L.LogDebug("global geoip: request blocked",
		"ip", clientIP,
		"country", country,
		"reason", reason)
}
