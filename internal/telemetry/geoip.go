package telemetry

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

var (
	geoDB     *geoip2.Reader
	geoOnce   sync.Once
	geoDBPath string
)

// InitGeoIP initializes the global GeoIP database for background country resolution.
func InitGeoIP(dbPath string) error {
	if dbPath == "" {
		dbPath = os.Getenv("GATEON_GEOIP_DB_PATH")
	}
	if dbPath == "" {
		return nil // Not configured
	}

	db, err := geoip2.Open(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open GeoIP database at %s: %w", dbPath, err)
	}

	geoDB = db
	geoDBPath = dbPath
	return nil
}

// ResolveIPInfo resolves an IP address to country code, city name, latitude and longitude.
func ResolveIPInfo(ipStr string) (country, city string, lat, lon float64) {
	if geoDB == nil {
		return "XX", "", 0, 0
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "XX", "", 0, 0
	}

	// Try City database first
	if record, err := geoDB.City(ip); err == nil {
		country = strings.ToUpper(record.Country.IsoCode)
		city = record.City.Names["en"]
		lat = record.Location.Latitude
		lon = record.Location.Longitude
		if country == "" {
			country = "XX"
		}
		return
	}

	// Fallback to Country database if City fails
	if record, err := geoDB.Country(ip); err == nil {
		country = strings.ToUpper(record.Country.IsoCode)
		if country == "" {
			country = "XX"
		}
		// Use default country coordinates if city/location not available
		lat, lon = GetCountryCoordinates(country)
		return
	}

	return "XX", "", 0, 0
}

// ResolveCountry resolves an IP address to an ISO 3166-1 alpha-2 country code.
// Returns "XX" if not found or on error.
func ResolveCountry(ipStr string) string {
	if geoDB == nil {
		return "XX"
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "XX"
	}

	record, err := geoDB.Country(ip)
	if err != nil {
		return "XX"
	}

	code := strings.ToUpper(record.Country.IsoCode)
	if code == "" {
		return "XX"
	}
	return code
}

// CloseGeoIP closes the global GeoIP database.
func CloseGeoIP() error {
	if geoDB != nil {
		return geoDB.Close()
	}
	return nil
}

// GeoIPResolver implements request.CountryResolver
type GeoIPResolver struct{}

func (g *GeoIPResolver) Resolve(ip string) string {
	return ResolveCountry(ip)
}
