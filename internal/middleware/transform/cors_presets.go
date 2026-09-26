// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gsoultan/gateon/internal/middleware/kind"
)

// CORSPreset represents a predefined CORS configuration.
type CORSPreset struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           int
}

var corsPresets = map[string]CORSPreset{
	"permissive": {
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   defaultCORSMethods(),
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"*"},
		AllowCredentials: true,
		MaxAge:           86400,
	},
	"standard": {
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", kind.HeaderAuthorization, kind.HeaderAccept},
		ExposedHeaders:   []string{"Content-Length", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           3600,
	},
	"grpc-web": {
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "X-User-Agent", "X-Grpc-Web", "Grpc-Timeout"},
		ExposedHeaders:   []string{"Grpc-Status", "Grpc-Message", "Grpc-Encoding", "Grpc-Accept-Encoding", "X-Grpc-Web", "X-Accept-Content-Transfer-Encoding", "X-Accept-Response-Streaming"},
		AllowCredentials: true,
		MaxAge:           86400,
	},
	"restricted": {
		AllowedOrigins:   []string{},
		AllowedMethods:   []string{"GET"},
		AllowedHeaders:   []string{kind.HeaderAccept},
		ExposedHeaders:   []string{},
		AllowCredentials: false,
		MaxAge:           600,
	},
}

// CORSPresetBackend hands a route's CORS to its backend: the cors middleware
// answers no preflight, adds no header, and the proxy strips none of the
// backend's. It is what a route whose backend enforces its own origin
// allowlist needs -- such a backend refuses an origin by leaving
// Access-Control-Allow-Origin off, and a route with no cors middleware reads
// that silence as "no CORS here" and supplies the permissive default
// (ADR-0015).
const CORSPresetBackend = "backend"

// IsBackendCORS reports whether a cors middleware's config hands the route's
// CORS to its backend.
func IsBackendCORS(cfg map[string]string) bool {
	return strings.EqualFold(strings.TrimSpace(cfg["preset"]), CORSPresetBackend)
}

// CheckCORSPreset refuses a preset name that names no preset. One was ignored,
// leaving the lists empty, which rs/cors reads as every origin: "restriced",
// a letter short of the locked-down preset, allowed anyone.
func CheckCORSPreset(name string) error {
	if strings.TrimSpace(name) == "" {
		return nil
	}
	if _, ok := GetCORSPreset(name); ok {
		return nil
	}
	names := make([]string, 0, len(corsPresets))
	for n := range corsPresets {
		names = append(names, n)
	}
	slices.Sort(names)
	return fmt.Errorf("no such preset; the presets are %s, and %q for a cors middleware",
		strings.Join(names, ", "), CORSPresetBackend)
}

// GetCORSPreset returns a CORS preset by name.
func GetCORSPreset(name string) (CORSPreset, bool) {
	p, ok := corsPresets[strings.ToLower(name)]
	return p, ok
}

// ApplyCORSPreset applies a preset to a CORSConfig, allowing overrides.
func ApplyCORSPreset(cfg map[string]string, base CORSConfig) CORSConfig {
	presetName := cfg["preset"]
	if presetName == "" {
		return base
	}

	preset, ok := GetCORSPreset(presetName)
	if !ok {
		return base
	}

	// Apply preset values if not explicitly provided in cfg
	if _, ok := cfg["allowed_origins"]; !ok && len(base.AllowedOrigins) == 0 {
		base.AllowedOrigins = preset.AllowedOrigins
	}
	if _, ok := cfg["allowed_methods"]; !ok && len(base.AllowedMethods) == 0 {
		base.AllowedMethods = preset.AllowedMethods
	}
	if _, ok := cfg["allowed_headers"]; !ok && len(base.AllowedHeaders) == 0 {
		base.AllowedHeaders = preset.AllowedHeaders
	}
	if _, ok := cfg["exposed_headers"]; !ok && len(base.ExposedHeaders) == 0 {
		base.ExposedHeaders = preset.ExposedHeaders
	}
	if _, ok := cfg["allow_credentials"]; !ok {
		base.AllowCredentials = preset.AllowCredentials
	}
	if _, ok := cfg["max_age"]; !ok && base.MaxAge == 0 {
		base.MaxAge = preset.MaxAge
	}
	// "Restricted" lists no origins because it means none, and rs/cors reads
	// an empty list as every origin: the preset the dashboard offers as the
	// locked-down choice answered any Origin with Access-Control-Allow-Origin: *.
	if presetName == "restricted" && len(base.AllowedOrigins) == 0 {
		base.DenyAllOrigins = true
	}

	return base
}
