// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/oschwald/geoip2-golang"
)

func NewGeoIP(cfg map[string]string) (kind.Middleware, error) {
	allow := kind.ParseListStrict(cfg["allow_countries"])
	deny := kind.ParseListStrict(cfg["deny_countries"])
	// A code that is not one never matches: on a deny list it refuses no one,
	// silently. Refused at build, so at save (ADR 0043/0044).
	if err := validateCountryCodes(allow, deny); err != nil {
		return nil, err
	}
	return GeoIP(GeoIPConfig{
		DBPath:          strings.TrimSpace(cfg["db_path"]),
		AllowCountries:  allow,
		DenyCountries:   deny,
		TrustCloudflare: request.ParseTrustCloudflare(cfg["trust_cloudflare_headers"]),
	})
}

// geoDatabaseHint says what to install, and where, to make a country list work.
const geoDatabaseHint = "install a MaxMind GeoLite2 City or Country database: upload the .mmdb under " +
	"Settings > GeoIP, download it there with a MaxMind licence key, or point geoip.db_path " +
	"(or GATEON_GEOIP_DB_PATH) at it"

// ErrGeoIPDatabaseRequired refuses a global country list saved while no
// database can place a client in a country.
var ErrGeoIPDatabaseRequired = errors.New("geoip: a country block or allow list needs a GeoIP " +
	"database, and none is loaded. Every client would resolve to the unknown country \"XX\", so a " +
	"block list would refuse no one and an allow list would refuse everyone. To fix it, " + geoDatabaseHint)

// ValidateGeoIPSave refuses a global GeoIP change that would save a country
// list the gateway cannot enforce: one naming something that is not a country
// code, or one with no database to resolve clients against (truth T1, ADR
// 0044). The global "Blocked Countries" used to save with success on every
// default install -- which has no database -- and block nobody.
//
// A list that is not being changed is not re-judged, so a database that
// vanished after the list was saved does not make every unrelated settings
// save fail; the geofence says so at runtime instead (GeoFenceState).
func ValidateGeoIPSave(stored, proposed *gateonv1.GeoIPConfig) error {
	if proposed == nil || sameGeofence(stored, proposed) {
		return nil
	}
	if err := validateCountryCodes(proposed.GetBlockedCountries(), proposed.GetAllowedCountries()); err != nil {
		return err
	}
	if !proposed.GetEnabled() || !hasCountryList(proposed) {
		return nil
	}
	if telemetry.GeoIPLoaded() || databaseOpens(proposed.GetDbPath()) {
		return nil
	}
	return ErrGeoIPDatabaseRequired
}

func hasCountryList(g *gateonv1.GeoIPConfig) bool {
	return len(g.GetBlockedCountries())+len(g.GetAllowedCountries()) > 0
}

// sameGeofence reports whether two configs enforce the same thing: both
// switched off, or both on with the same lists.
func sameGeofence(a, b *gateonv1.GeoIPConfig) bool {
	if a.GetEnabled() != b.GetEnabled() {
		return false
	}
	return maps.Equal(countrySet(a.GetBlockedCountries()), countrySet(b.GetBlockedCountries())) &&
		maps.Equal(countrySet(a.GetAllowedCountries()), countrySet(b.GetAllowedCountries()))
}

func validateCountryCodes(lists ...[]string) error {
	for _, list := range lists {
		for _, c := range list {
			if !isCountryCode(normalizeCountry(c)) {
				return fmt.Errorf("geoip: %q is not a two-letter ISO 3166 country code, so it would match no client", c)
			}
		}
	}
	return nil
}

func isCountryCode(c string) bool {
	return len(c) == 2 && c[0] >= 'A' && c[0] <= 'Z' && c[1] >= 'A' && c[1] <= 'Z'
}

// databaseOpens reports whether path is a GeoIP database the reader opens: a
// save that names one is installing it, and applying the save loads it.
func databaseOpens(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	db, err := geoip2.Open(path)
	if err != nil {
		return false
	}
	_ = db.Close()
	return true
}

// Geofence states reported by GeoFenceState.
const (
	GeoFenceOff = "off"
	// GeoFenceActive: a database is loaded and a list is enforced.
	GeoFenceActive = "active"
	// GeoFenceBlockListInactive: no database, so the block list refuses no one.
	GeoFenceBlockListInactive = "block_list_inactive"
	// GeoFenceRefusingAll: no database, so the allow list refuses everyone.
	GeoFenceRefusingAll = "allow_list_refusing_all"
)

// refusesUnknown reports whether the global geofence refuses a client in the
// unknown country "XX" -- which, with no database, is every client: the block
// list names XX, or an allow list does not.
func refusesUnknown(g *gateonv1.GeoIPConfig) bool {
	const unknown = "XX"
	if _, blocked := countrySet(g.GetBlockedCountries())[unknown]; blocked {
		return true
	}
	allowed := countrySet(g.GetAllowedCountries())
	_, ok := allowed[unknown]
	return len(allowed) > 0 && !ok
}

// GeoFenceState is what the global geofence does now, and why, for the
// dashboard: whether its lists are enforced, or what happens instead.
func GeoFenceState(g *gateonv1.GeoIPConfig, dbLoaded bool) (state, reason string) {
	switch {
	case !g.GetEnabled() || !hasCountryList(g):
		return GeoFenceOff, "No country list is in force."
	case dbLoaded:
		return GeoFenceActive, "Country lists are enforced on every HTTP entrypoint."
	case refusesUnknown(g):
		return GeoFenceRefusingAll, "No GeoIP database is loaded, so every client resolves to the unknown " +
			"country \"XX\" and the country lists refuse every request. To fix it, " + geoDatabaseHint + "."
	default:
		return GeoFenceBlockListInactive, "No GeoIP database is loaded, so every client resolves to the " +
			"unknown country and the block list refuses no one. To fix it, " + geoDatabaseHint + "."
	}
}
