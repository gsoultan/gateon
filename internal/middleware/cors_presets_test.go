// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"testing"
)

func TestApplyCORSPreset(t *testing.T) {
	tests := []struct {
		name     string
		cfg      map[string]string
		base     CORSConfig
		validate func(t *testing.T, got CORSConfig)
	}{
		{
			name: "Permissive Preset",
			cfg:  map[string]string{"preset": "permissive"},
			base: CORSConfig{},
			validate: func(t *testing.T, got CORSConfig) {
				if len(got.AllowedOrigins) != 1 || got.AllowedOrigins[0] != "*" {
					t.Errorf("expected allowed origins [*], got %v", got.AllowedOrigins)
				}
				if !got.AllowCredentials {
					t.Error("expected allow credentials to be true")
				}
				if got.MaxAge != 86400 {
					t.Errorf("expected max age 86400, got %d", got.MaxAge)
				}
			},
		},
		{
			name: "Preset with Overrides",
			cfg: map[string]string{
				"preset":          "permissive",
				"allowed_origins": "https://example.com",
				"max_age":         "3600",
			},
			base: CORSConfig{
				AllowedOrigins: []string{"https://example.com"},
				MaxAge:         3600,
			},
			validate: func(t *testing.T, got CORSConfig) {
				if len(got.AllowedOrigins) != 1 || got.AllowedOrigins[0] != "https://example.com" {
					t.Errorf("expected allowed origins [https://example.com], got %v", got.AllowedOrigins)
				}
				if got.MaxAge != 3600 {
					t.Errorf("expected max age 3600, got %d", got.MaxAge)
				}
				// Still gets other permissive values
				if !got.AllowCredentials {
					t.Error("expected allow credentials to be true")
				}
			},
		},
		{
			name: "Standard Preset",
			cfg:  map[string]string{"preset": "standard"},
			base: CORSConfig{},
			validate: func(t *testing.T, got CORSConfig) {
				if len(got.AllowedMethods) != 3 {
					t.Errorf("expected 3 allowed methods, got %d", len(got.AllowedMethods))
				}
			},
		},
		{
			name: "gRPC-Web Preset",
			cfg:  map[string]string{"preset": "grpc-web"},
			base: CORSConfig{},
			validate: func(t *testing.T, got CORSConfig) {
				if !contains(got.AllowedHeaders, "X-Grpc-Web") {
					t.Error("expected X-Grpc-Web in allowed headers")
				}
			},
		},
		{
			name: "Unknown Preset",
			cfg:  map[string]string{"preset": "nonexistent"},
			base: CORSConfig{AllowedOrigins: []string{"*"}},
			validate: func(t *testing.T, got CORSConfig) {
				if len(got.AllowedOrigins) != 1 || got.AllowedOrigins[0] != "*" {
					t.Errorf("expected original allowed origins, got %v", got.AllowedOrigins)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ApplyCORSPreset(tc.cfg, tc.base)
			tc.validate(t, got)
		})
	}
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
