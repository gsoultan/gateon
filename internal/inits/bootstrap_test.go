// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package inits

import (
	"os"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestEmptyConfigDoesNotClobberTheEnvironment is the bug this package was
// hiding. Four of the TLS variables were written unconditionally, and setEnv on
// an empty string does not clear a variable -- it sets it to "". So a
// global.json with a tls block that omits an email erased GATEON_TLS_EMAIL from
// a deployment that had exported it on purpose, and the operator's only clue
// was TLS behaving as if they had configured nothing.
func TestEmptyConfigDoesNotClobberTheEnvironment(t *testing.T) {
	vars := map[string]string{
		"GATEON_TLS_EMAIL":            "ops@example.com",
		"GATEON_TLS_MIN_VERSION":      "1.3",
		"GATEON_TLS_MAX_VERSION":      "1.3",
		"GATEON_TLS_CLIENT_AUTH_TYPE": "RequireAndVerifyClientCert",
	}
	for k, v := range vars {
		t.Setenv(k, v)
	}

	// A tls block that carries nothing but the on switch.
	applyGlobalEnv(&gateonv1.GlobalConfig{Tls: &gateonv1.TlsConfig{Enabled: true}})

	for k, want := range vars {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, want %q; an empty config field overwrote a value "+
				"the operator set in the environment", k, got, want)
		}
	}
}

func TestConfiguredValuesReachTheEnvironment(t *testing.T) {
	for _, k := range []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT", "REDIS_ADDR", "GATEON_TLS_ENABLED",
		"GATEON_TLS_EMAIL", "GATEON_TLS_DOMAINS", "GATEON_TLS_MIN_VERSION",
		"GATEON_TLS_MAX_VERSION", "GATEON_TLS_CLIENT_AUTH_TYPE",
		"GATEON_TLS_CIPHER_SUITES",
	} {
		t.Setenv(k, "")
	}

	applyGlobalEnv(&gateonv1.GlobalConfig{
		Otel:  &gateonv1.OtelConfig{Endpoint: "http://collector:4318"},
		Redis: &gateonv1.RedisConfig{Addr: "cache:6379"},
		Tls: &gateonv1.TlsConfig{
			Enabled:        true,
			Email:          "tls@example.com",
			Domains:        []string{"a.example.com", "b.example.com"},
			MinTlsVersion:  "1.2",
			MaxTlsVersion:  "1.3",
			ClientAuthType: "NoClientCert",
			CipherSuites:   []string{"TLS_AES_128_GCM_SHA256"},
		},
	})

	for k, want := range map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318",
		"REDIS_ADDR":                  "cache:6379",
		"GATEON_TLS_ENABLED":          "true",
		"GATEON_TLS_EMAIL":            "tls@example.com",
		"GATEON_TLS_DOMAINS":          "a.example.com,b.example.com",
		"GATEON_TLS_MIN_VERSION":      "1.2",
		"GATEON_TLS_MAX_VERSION":      "1.3",
		"GATEON_TLS_CLIENT_AUTH_TYPE": "NoClientCert",
		"GATEON_TLS_CIPHER_SUITES":    "TLS_AES_128_GCM_SHA256",
	} {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

// TestTLSDisabledIsPublished pins the deliberate exception: false is a real
// value for a bool, so omitting it would make "off in config" look identical to
// "config says nothing".
func TestTLSDisabledIsPublished(t *testing.T) {
	t.Setenv("GATEON_TLS_ENABLED", "true")

	applyGlobalEnv(&gateonv1.GlobalConfig{Tls: &gateonv1.TlsConfig{Enabled: false}})

	if got := os.Getenv("GATEON_TLS_ENABLED"); got != "false" {
		t.Errorf("GATEON_TLS_ENABLED = %q, want %q; config turning TLS off must "+
			"reach the environment", got, "false")
	}
}

func TestNilSectionsAreSkipped(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "keep-me")
	t.Setenv("REDIS_ADDR", "keep-me-too")
	t.Setenv("GATEON_TLS_ENABLED", "keep-me-three")

	applyGlobalEnv(&gateonv1.GlobalConfig{})
	applyGlobalEnv(nil)

	for k, want := range map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT": "keep-me",
		"REDIS_ADDR":                  "keep-me-too",
		"GATEON_TLS_ENABLED":          "keep-me-three",
	} {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, want %q; an absent config section must not write",
				k, got, want)
		}
	}
}

func TestHasAuthDatabase(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		auth *gateonv1.AuthConfig
		want bool
	}{
		{"nil", nil, false},
		{"empty", &gateonv1.AuthConfig{}, false},
		{"database url", &gateonv1.AuthConfig{DatabaseUrl: "postgres://x"}, true},
		{"sqlite path", &gateonv1.AuthConfig{SqlitePath: "/var/lib/gateon.db"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := hasAuthDatabase(tc.auth); got != tc.want {
				t.Errorf("hasAuthDatabase = %v, want %v", got, tc.want)
			}
		})
	}
}
