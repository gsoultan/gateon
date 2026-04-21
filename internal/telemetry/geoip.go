package telemetry

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

type publicIPInfo struct {
	Status      string  `json:"status"`
	CountryCode string  `json:"countryCode"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

var (
	geoDB     *geoip2.Reader
	geoMu     sync.RWMutex
	geoDBPath string

	ipCache   = make(map[string]publicIPInfo)
	cacheMu   sync.RWMutex
	lastFetch time.Time
)

// InitGeoIP initializes the global GeoIP database for background country resolution.
func InitGeoIP(dbPath string) error {
	geoMu.Lock()
	defer geoMu.Unlock()

	if dbPath == "" {
		dbPath = os.Getenv("GATEON_GEOIP_DB_PATH")
	}
	if dbPath == "" {
		// Look in default location
		defaultPath := filepath.Join("geoip", "GeoLite2-City.mmdb")
		if _, err := os.Stat(defaultPath); err == nil {
			dbPath = defaultPath
		}
	}
	if dbPath == "" {
		return nil // Not configured
	}

	if geoDB != nil {
		_ = geoDB.Close()
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
	geoMu.RLock()
	dbLoaded := geoDB != nil
	if dbLoaded {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			if record, err := geoDB.City(ip); err == nil {
				country = strings.ToUpper(record.Country.IsoCode)
				city = record.City.Names["en"]
				lat = record.Location.Latitude
				lon = record.Location.Longitude
				if country != "" {
					geoMu.RUnlock()
					if lat == 0 && lon == 0 {
						lat, lon = GetCountryCoordinates(country)
					}
					return
				}
			}

			// Fallback to Country database if City fails
			if record, err := geoDB.Country(ip); err == nil {
				country = strings.ToUpper(record.Country.IsoCode)
				if country != "" {
					geoMu.RUnlock()
					lat, lon = GetCountryCoordinates(country)
					return
				}
			}
		}
	}
	geoMu.RUnlock()

	// Fallback to public API if DB is missing or IP not found in DB
	// Only for non-local IPs
	if isPublicIP(ipStr) {
		return resolveIPPublic(ipStr)
	}

	return "XX", "", 0, 0
}

func isPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return false
	}
	return true
}

func resolveIPPublic(ipStr string) (country, city string, lat, lon float64) {
	cacheMu.RLock()
	if info, ok := ipCache[ipStr]; ok {
		cacheMu.RUnlock()
		return info.CountryCode, info.City, info.Lat, info.Lon
	}
	cacheMu.RUnlock()

	// Rate limit: 1 request per second to public API
	cacheMu.Lock()
	if time.Since(lastFetch) < time.Second {
		cacheMu.Unlock()
		return "XX", "", 0, 0
	}
	lastFetch = time.Now()
	cacheMu.Unlock()

	url := fmt.Sprintf("http://ip-api.com/json/%s", ipStr)
	resp, err := httpGet(url, 2*time.Second) // Fixed call
	if err != nil {
		return "XX", "", 0, 0
	}
	defer resp.Body.Close()

	var info publicIPInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "XX", "", 0, 0
	}

	if info.Status != "success" {
		return "XX", "", 0, 0
	}

	cacheMu.Lock()
	if len(ipCache) > 1000 { // Simple cache eviction
		for k := range ipCache {
			delete(ipCache, k)
			break
		}
	}
	ipCache[ipStr] = info
	cacheMu.Unlock()

	return info.CountryCode, info.City, info.Lat, info.Lon
}

// Wrapper for http.Get with timeout
func httpGet(url string, timeout time.Duration) (*http.Response, error) {
	client := &http.Client{Timeout: timeout}
	return client.Get(url)
}

// ResolveCountry resolves an IP address to an ISO 3166-1 alpha-2 country code.
// Returns "XX" if not found or on error.
func ResolveCountry(ipStr string) string {
	geoMu.RLock()
	defer geoMu.RUnlock()

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
	geoMu.Lock()
	defer geoMu.Unlock()

	if geoDB != nil {
		return geoDB.Close()
	}
	return nil
}

// DownloadGeoIP downloads the GeoLite2-City database from MaxMind using the provided license key.
func DownloadGeoIP(licenseKey string) error {
	if licenseKey == "" {
		return fmt.Errorf("maxmind license key is required")
	}

	url := fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%s&suffix=tar.gz", licenseKey)

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download GeoIP database: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("maxmind download failed with status: %s", resp.Status)
	}

	// Create geoip directory if it doesn't exist
	if err := os.MkdirAll("geoip", 0755); err != nil {
		return fmt.Errorf("failed to create geoip directory: %w", err)
	}

	// Extract tar.gz
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	var found bool
	destPath := filepath.Join("geoip", "GeoLite2-City.mmdb")

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar entry: %w", err)
		}

		if strings.HasSuffix(header.Name, ".mmdb") {
			f, err := os.Create(destPath)
			if err != nil {
				return fmt.Errorf("failed to create destination file: %w", err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("failed to copy mmdb content: %w", err)
			}
			f.Close()
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("no .mmdb file found in the downloaded archive")
	}

	// Reload database
	return InitGeoIP(destPath)
}

// GetGeoIPStatus returns information about the current GeoIP database.
func GetGeoIPStatus() (exists bool, path string, info string) {
	geoMu.RLock()
	defer geoMu.RUnlock()

	if geoDB == nil {
		return false, "", "Database not loaded"
	}

	info = "MaxMind GeoLite2 (City)"
	if metadata := geoDB.Metadata(); metadata.Description != nil {
		if desc, ok := metadata.Description["en"]; ok {
			info = desc
		}
	}

	return true, geoDBPath, info
}

// GeoIPResolver implements request.CountryResolver
type GeoIPResolver struct{}

func (g *GeoIPResolver) Resolve(ip string) string {
	return ResolveCountry(ip)
}
