package telemetry

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
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

// MaxMind GeoLite2 edition identifiers and their default on-disk locations.
const (
	editionCity    = "GeoLite2-City"
	editionASN     = "GeoLite2-ASN"
	editionCountry = "GeoLite2-Country"

	defaultCityDBPath    = "geoip/GeoLite2-City.mmdb"
	defaultASNDBPath     = "geoip/GeoLite2-ASN.mmdb"
	defaultCountryDBPath = "geoip/GeoLite2-Country.mmdb"

	geoDir = "geoip"
)

var (
	geoDB     *geoip2.Reader // City (or Country) edition used for geolocation.
	asnDB     *geoip2.Reader // Optional GeoLite2-ASN edition used for ASN lookups.
	countryDB *geoip2.Reader // Optional GeoLite2-Country edition used as a fallback.
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
		defaultPath := filepath.FromSlash(defaultCityDBPath)
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
func ResolveIPInfo(ctx context.Context, ipStr string) (country, city string, lat, lon float64) {
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
		return resolveIPPublic(ctx, ipStr)
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

func resolveIPPublic(ctx context.Context, ipStr string) (country, city string, lat, lon float64) {
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
	resp, err := httpGet(ctx, url, 2*time.Second)
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

// Wrapper for http.Get with timeout and context
func httpGet(ctx context.Context, url string, timeout time.Duration) (*http.Response, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
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

// InitGeoIPASN initializes the optional GeoLite2-ASN reader used to resolve the
// autonomous system of an IP address. A missing database is not an error: ASN
// resolution is treated as optional so existing deployments keep working.
func InitGeoIPASN(dbPath string) error {
	geoMu.Lock()
	defer geoMu.Unlock()

	if dbPath == "" {
		dbPath = os.Getenv("GATEON_GEOIP_ASN_DB_PATH")
	}
	if dbPath == "" {
		defaultPath := filepath.FromSlash(defaultASNDBPath)
		if _, err := os.Stat(defaultPath); err == nil {
			dbPath = defaultPath
		}
	}
	if dbPath == "" {
		return nil // Not configured; ASN resolution stays disabled.
	}

	if asnDB != nil {
		_ = asnDB.Close()
		asnDB = nil
	}

	db, err := geoip2.Open(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open GeoIP ASN database at %s: %w", dbPath, err)
	}

	asnDB = db
	return nil
}

// InitGeoIPCountry initializes the optional GeoLite2-Country reader. It is used
// as an additional fallback and is treated as optional like the ASN database.
func InitGeoIPCountry(dbPath string) error {
	geoMu.Lock()
	defer geoMu.Unlock()

	if dbPath == "" {
		dbPath = os.Getenv("GATEON_GEOIP_COUNTRY_DB_PATH")
	}
	if dbPath == "" {
		defaultPath := filepath.FromSlash(defaultCountryDBPath)
		if _, err := os.Stat(defaultPath); err == nil {
			dbPath = defaultPath
		}
	}
	if dbPath == "" {
		return nil // Not configured.
	}

	if countryDB != nil {
		_ = countryDB.Close()
		countryDB = nil
	}

	db, err := geoip2.Open(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open GeoIP Country database at %s: %w", dbPath, err)
	}

	countryDB = db
	return nil
}

// ResolveASN resolves an IP address to its autonomous system, formatted as
// "AS<number> <organization>". It returns "" when the ASN database is not
// loaded, the IP is invalid, or no ASN is associated with the address.
func ResolveASN(ipStr string) string {
	geoMu.RLock()
	defer geoMu.RUnlock()

	if asnDB == nil {
		return ""
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	record, err := asnDB.ASN(ip)
	if err != nil || record == nil || record.AutonomousSystemNumber == 0 {
		return ""
	}

	org := strings.TrimSpace(record.AutonomousSystemOrganization)
	if org == "" {
		return fmt.Sprintf("AS%d", record.AutonomousSystemNumber)
	}
	return fmt.Sprintf("AS%d %s", record.AutonomousSystemNumber, org)
}

// CloseGeoIP closes all loaded GeoIP databases.
func CloseGeoIP() error {
	geoMu.Lock()
	defer geoMu.Unlock()

	var errs []error
	if geoDB != nil {
		if err := geoDB.Close(); err != nil {
			errs = append(errs, err)
		}
		geoDB = nil
	}
	if asnDB != nil {
		if err := asnDB.Close(); err != nil {
			errs = append(errs, err)
		}
		asnDB = nil
	}
	if countryDB != nil {
		if err := countryDB.Close(); err != nil {
			errs = append(errs, err)
		}
		countryDB = nil
	}
	return errors.Join(errs...)
}

// geoIPEdition describes a MaxMind GeoLite2 edition to download together with
// its on-disk destination and the reload hook that swaps the in-memory reader.
type geoIPEdition struct {
	id       string
	destPath string
	reload   func(string) error
	required bool
}

// geoIPEditions returns the editions Gateon downloads from MaxMind. The City
// edition is required (it powers geolocation); ASN and Country are optional and
// a failure to fetch them must not break the City update.
func geoIPEditions() []geoIPEdition {
	return []geoIPEdition{
		{id: editionCity, destPath: filepath.FromSlash(defaultCityDBPath), reload: InitGeoIP, required: true},
		{id: editionASN, destPath: filepath.FromSlash(defaultASNDBPath), reload: InitGeoIPASN, required: false},
		{id: editionCountry, destPath: filepath.FromSlash(defaultCountryDBPath), reload: InitGeoIPCountry, required: false},
	}
}

// DownloadGeoIP downloads the configured GeoLite2 editions (City, ASN and
// Country) from MaxMind using the provided license key. The City edition is
// mandatory; optional editions are downloaded on a best-effort basis and their
// failures are aggregated and returned without aborting the whole update.
func DownloadGeoIP(licenseKey string) error {
	if licenseKey == "" {
		return fmt.Errorf("maxmind license key is required")
	}

	if err := os.MkdirAll(geoDir, 0o755); err != nil {
		return fmt.Errorf("failed to create geoip directory: %w", err)
	}

	var optionalErrs []error
	for _, edition := range geoIPEditions() {
		if err := downloadGeoIPEdition(licenseKey, edition); err != nil {
			if edition.required {
				return err
			}
			optionalErrs = append(optionalErrs, err)
		}
	}

	return errors.Join(optionalErrs...)
}

// downloadGeoIPEdition downloads a single MaxMind edition, extracts the embedded
// .mmdb file to its destination and reloads the associated reader.
func downloadGeoIPEdition(licenseKey string, edition geoIPEdition) error {
	url := fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz", edition.id, licenseKey)

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download %s database: %w", edition.id, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("maxmind download of %s failed with status: %s", edition.id, resp.Status)
	}

	if err := extractMMDB(resp.Body, edition.destPath); err != nil {
		return fmt.Errorf("%s: %w", edition.id, err)
	}

	return edition.reload(edition.destPath)
}

// extractMMDB reads a gzip-compressed tar stream and writes the first contained
// .mmdb file to destPath.
func extractMMDB(body io.Reader, destPath string) error {
	gzr, err := gzip.NewReader(body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar entry: %w", err)
		}

		if !strings.HasSuffix(header.Name, ".mmdb") {
			continue
		}

		f, err := os.Create(destPath)
		if err != nil {
			return fmt.Errorf("failed to create destination file: %w", err)
		}
		if _, err := io.Copy(f, tr); err != nil {
			_ = f.Close()
			return fmt.Errorf("failed to copy mmdb content: %w", err)
		}
		_ = f.Close()
		return nil
	}

	return fmt.Errorf("no .mmdb file found in the downloaded archive")
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
