// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/oschwald/geoip2-golang"
)

// maxMMDBBytes bounds a single file unpacked from the MaxMind archive. A
// GeoLite2-City database is ~70 MiB; 256 MiB leaves generous headroom while
// still refusing an archive that decompresses without end.
const maxMMDBBytes int64 = 256 << 20

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

	countryCache *lru.ARCCache
	asnCache     *lru.ARCCache
	geoCacheOnce sync.Once

	publicIPCache   string
	lastIPFetch     time.Time
	publicIPCacheMu sync.RWMutex
)

const publicIPCacheTTL = 1 * time.Hour

// GetPublicIP returns the server's public IP address by querying multiple providers.
func GetPublicIP(ctx context.Context) string {
	publicIPCacheMu.RLock()
	if publicIPCache != "" && time.Since(lastIPFetch) < publicIPCacheTTL {
		ip := publicIPCache
		publicIPCacheMu.RUnlock()
		return ip
	}
	publicIPCacheMu.RUnlock()

	publicIPCacheMu.Lock()
	defer publicIPCacheMu.Unlock()

	// Double check after acquiring lock
	if publicIPCache != "" && time.Since(lastIPFetch) < publicIPCacheTTL {
		return publicIPCache
	}

	providers := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://ipinfo.io/ip",
		"https://ident.me",
		"https://v4.ident.me",
	}

	// Use a slightly longer timeout for the whole process but keep individual attempts short
	client := http.Client{Timeout: 3 * time.Second}
	for _, url := range providers {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusOK {
			continue
		}

		ipStr := string(bytes.TrimSpace(body))
		if net.ParseIP(ipStr) != nil {
			publicIPCache = ipStr
			lastIPFetch = time.Now()
			return ipStr
		}
	}

	publicIPCache = "unknown"
	lastIPFetch = time.Now()
	return "unknown"
}

// InitGeoIP initializes the global GeoIP database for background country resolution.
//
// The new database is opened before the old one is closed, and a path that
// does not open leaves the old one in force. It used to close the loaded
// database first, so saving a mistyped db_path in Settings -- or an upload the
// reader rejects -- took geolocation away for the life of the process, and
// with it every country geofence, until the next restart (ADR 0044).
func InitGeoIP(dbPath string) error {
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

	db, err := geoip2.Open(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open GeoIP database at %s: %w", dbPath, err)
	}

	geoMu.Lock()
	defer geoMu.Unlock()
	// Closed after the swap, under the write lock, so no lookup holds it.
	if geoDB != nil {
		_ = geoDB.Close()
	}
	geoDB = db
	geoDBPath = dbPath
	geoChangedLocked()
	return nil
}

// geoLoaded is whether a database that resolves countries is loaded: the
// City database, or the Country one. Read on the request path by the global
// geofence, so it is an atomic rather than a read of geoDB under geoMu.
var geoLoaded atomic.Bool

// GeoIPLoaded reports whether a database that resolves countries is loaded.
// Without one every address resolves to the unknown country "XX", which no
// country list can tell apart.
func GeoIPLoaded() bool { return geoLoaded.Load() }

// geoChangedLocked records a change of database. Cached answers came from the
// previous one, so they are dropped. Called with geoMu held for writing.
func geoChangedLocked() {
	geoLoaded.Store(geoDB != nil || countryDB != nil)
	initGeoCaches()
	if countryCache != nil {
		countryCache.Purge()
	}
	if asnCache != nil {
		asnCache.Purge()
	}
}

// ResolveIPInfo resolves an IP address to country code, city name, latitude and longitude.
func ResolveIPInfo(ctx context.Context, ipStr string) (country, city string, lat, lon float64) {
	return ResolveIPInfoCustom(ctx, ipStr, false)
}

// ResolveIPInfoFast resolves an IP address using only the local database.
func ResolveIPInfoFast(ipStr string) (country, city string, lat, lon float64) {
	return ResolveIPInfoCustom(context.Background(), ipStr, true)
}

// ResolveIPInfoCustom resolves an IP address to country code, city name,
// latitude and longitude from the local database only; "XX" when there is none
// or it does not know the address. fastOnly is kept for callers and no longer
// changes anything: every lookup is local.
func ResolveIPInfoCustom(ctx context.Context, ipStr string, fastOnly bool) (country, city string, lat, lon float64) {
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

	// Unknown, not asked about elsewhere. Without a local database every
	// client address used to be sent in plaintext to http://ip-api.com, one
	// request a second on the analysis path: personal data shipped to a third
	// party nobody configured, on every default install (the database needs a
	// licence key). Locations need a local MaxMind database; see the GeoIP
	// settings.
	return "XX", "", 0, 0
}

func initGeoCaches() {
	geoCacheOnce.Do(func() {
		countryCache, _ = lru.NewARC(4096)
		asnCache, _ = lru.NewARC(4096)
	})
}

// ResolveCountry resolves an IP address to an ISO 3166-1 alpha-2 country code.
// Returns "XX" if not found or on error.
func ResolveCountry(ipStr string) string {
	initGeoCaches()
	if countryCache != nil {
		if val, ok := countryCache.Get(ipStr); ok {
			return val.(string)
		}
	}

	geoMu.RLock()
	defer geoMu.RUnlock()

	// The City database answers country lookups too; a Country database
	// alone is enough for a geofence, and used to be ignored here.
	db := geoDB
	if db == nil {
		db = countryDB
	}
	if db == nil {
		return "XX"
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "XX"
	}

	record, err := db.Country(ip)
	if err != nil {
		return "XX"
	}

	code := strings.ToUpper(record.Country.IsoCode)
	if code == "" {
		code = "XX"
	}

	if countryCache != nil {
		countryCache.Add(ipStr, code)
	}
	return code
}

// InitGeoIPASN initializes the optional GeoLite2-ASN reader used to resolve the
// autonomous system of an IP address. A missing database is not an error: ASN
// resolution is treated as optional so existing deployments keep working.
func InitGeoIPASN(dbPath string) error {
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

	// Opened first, so a path that does not open keeps the loaded one.
	db, err := geoip2.Open(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open GeoIP ASN database at %s: %w", dbPath, err)
	}

	geoMu.Lock()
	defer geoMu.Unlock()
	if asnDB != nil {
		_ = asnDB.Close()
	}
	asnDB = db
	geoChangedLocked()
	return nil
}

// InitGeoIPCountry initializes the optional GeoLite2-Country reader. It is used
// as an additional fallback and is treated as optional like the ASN database.
func InitGeoIPCountry(dbPath string) error {
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

	// Opened first, so a path that does not open keeps the loaded one.
	db, err := geoip2.Open(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open GeoIP Country database at %s: %w", dbPath, err)
	}

	geoMu.Lock()
	defer geoMu.Unlock()
	if countryDB != nil {
		_ = countryDB.Close()
	}
	countryDB = db
	geoChangedLocked()
	return nil
}

// ResolveASN resolves an IP address to its autonomous system, formatted as
// "AS<number> <organization>". It returns "" when the ASN database is not
// loaded, the IP is invalid, or no ASN is associated with the address.
func ResolveASN(ipStr string) string {
	initGeoCaches()
	if asnCache != nil {
		if val, ok := asnCache.Get(ipStr); ok {
			return val.(string)
		}
	}

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
	var res string
	if org == "" {
		res = fmt.Sprintf("AS%d", record.AutonomousSystemNumber)
	} else {
		res = fmt.Sprintf("AS%d %s", record.AutonomousSystemNumber, org)
	}

	if asnCache != nil {
		asnCache.Add(ipStr, res)
	}
	return res
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
	geoChangedLocked()
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

	if err := os.MkdirAll(geoDir, 0o750); err != nil {
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

// geoIPDownloadURL is MaxMind's download endpoint. A variable so a test can
// point the downloader at a local address.
var geoIPDownloadURL = "https://download.maxmind.com/app/geoip_download"

// downloadGeoIPEdition downloads a single MaxMind edition, extracts the embedded
// .mmdb file to its destination and reloads the associated reader.
func downloadGeoIPEdition(licenseKey string, edition geoIPEdition) error {
	// Encoded, not formatted in: the key comes from the settings card as well as
	// from global config, and a formatted one containing "&" or "#" added
	// parameters to the request sent to MaxMind, or cut it short.
	query := url.Values{}
	query.Set("edition_id", edition.id)
	query.Set("license_key", licenseKey)
	query.Set("suffix", "tar.gz")
	downloadURL := geoIPDownloadURL + "?" + query.Encode()

	// #nosec G107 -- the scheme, host and path are MaxMind's fixed download
	// endpoint. The licence key -- from global config, or typed into the
	// settings card by an operator with write access -- is query-encoded, so it
	// cannot change them.
	resp, err := http.Get(downloadURL)
	if err != nil {
		// A transport failure is a *url.Error whose message embeds the full
		// URL, and the URL carries the licence key. The worker logs this error
		// and /v1/geoip/update writes it to the response, so the key was
		// reaching the system log stream. Keep the underlying cause only.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
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
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar entry: %w", err)
		}

		if !strings.HasSuffix(header.Name, ".mmdb") {
			continue
		}

		// #nosec G304 -- destPath is built from the fixed geoip directory and a
		// name filtered to .mmdb entries from the MaxMind archive.
		f, err := os.Create(destPath)
		if err != nil {
			return fmt.Errorf("failed to create destination file: %w", err)
		}
		// Bounded copy, not io.Copy. The tar stream is gzip-decompressed remote
		// content, so its uncompressed size is chosen by whoever served it — a
		// compromised mirror, a hijacked DNS answer or a proxy in the middle can
		// answer a few KB of gzip that expands until the disk is full. Writing
		// one byte past the ceiling is treated as hostile rather than truncated,
		// because a silently truncated mmdb would load as a corrupt database.
		written, err := io.Copy(f, io.LimitReader(tr, maxMMDBBytes+1))
		if err != nil {
			_ = f.Close()
			return fmt.Errorf("failed to copy mmdb content: %w", err)
		}
		if written > maxMMDBBytes {
			_ = f.Close()
			_ = os.Remove(destPath)
			return fmt.Errorf("mmdb entry %q exceeds the %d byte limit; refusing to unpack",
				header.Name, int64(maxMMDBBytes))
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
