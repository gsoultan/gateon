package middleware

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
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
func GeoIP(cfg GeoIPConfig) (Middleware, error) {
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

	trust := cfg.TrustCloudflare

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ShouldSkipMetrics(r) {
				next.ServeHTTP(w, r)
				return
			}
			activeRouteID := GetRouteName(r)

			clientIP := request.GetClientIP(r, trust)
			ip := net.ParseIP(clientIP)
			if ip == nil {
				http.Error(w, "Forbidden", http.StatusForbidden)
				logger.L.Debug().Str("ip", clientIP).Msg("geoip: invalid client IP")
				return
			}

			record, err := db.Country(ip)
			if err != nil {
				// Unknown IP or lookup error: allow by default to avoid blocking
				next.ServeHTTP(w, r)
				return
			}

			country := strings.ToUpper(record.Country.IsoCode)
			if country == "" {
				country = "XX"
			}

			_, denied := denySet[country]
			_, allowed := allowSet[country]

			if denied {
				telemetry.MiddlewareGeoIPBlockedTotal.WithLabelValues(activeRouteID, country).Inc()
				http.Error(w, "Forbidden", http.StatusForbidden)
				logger.L.Debug().
					Str("ip", clientIP).
					Str("country", country).
					Msg("geoip: request denied by country")
				return
			}

			if len(allowSet) > 0 && !allowed {
				telemetry.MiddlewareGeoIPBlockedTotal.WithLabelValues(activeRouteID, country).Inc()
				http.Error(w, "Forbidden", http.StatusForbidden)
				logger.L.Debug().
					Str("ip", clientIP).
					Str("country", country).
					Msg("geoip: request not in allow list")
				return
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}
