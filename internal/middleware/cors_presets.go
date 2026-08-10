// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"strings"
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
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"*"},
		AllowCredentials: true,
		MaxAge:           86400,
	},
	"standard": {
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "Accept"},
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
		AllowedHeaders:   []string{"Accept"},
		ExposedHeaders:   []string{},
		AllowCredentials: false,
		MaxAge:           600,
	},
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

	return base
}
