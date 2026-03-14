package middleware

import (
	"strings"

	"github.com/gateon/gateon/internal/request"
)

func (f *Factory) createGeoIP(cfg map[string]string) (Middleware, error) {
	return GeoIP(GeoIPConfig{
		DBPath:          strings.TrimSpace(cfg["db_path"]),
		AllowCountries:  parseListStrict(cfg["allow_countries"]),
		DenyCountries:   parseListStrict(cfg["deny_countries"]),
		TrustCloudflare: request.ParseTrustCloudflare(cfg["trust_cloudflare_headers"]),
	})
}
