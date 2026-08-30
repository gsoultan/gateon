// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func noEnvVars(string) string { return "" }

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// TestConfiguredServiceNameIsUsed is the regression guard: InitTracer was called
// with a hardcoded "server", so every gateway reported as the same service and
// instances were indistinguishable in a trace backend.
func TestConfiguredServiceNameIsUsed(t *testing.T) {
	got := ResolveServiceName(&gateonv1.OtelConfig{ServiceName: "edge-gateway-eu"}, noEnvVars)
	if got != "edge-gateway-eu" {
		t.Fatalf("ResolveServiceName() = %q, want the configured name", got)
	}
}

// The previous name is kept when nothing is configured. Changing it would
// silently rename an existing service in someone's trace backend and orphan the
// dashboards and alerts built on it.
func TestUnconfiguredKeepsThePreviousName(t *testing.T) {
	for _, tc := range []struct {
		name string
		conf *gateonv1.OtelConfig
	}{
		{"nil config", nil},
		{"empty config", &gateonv1.OtelConfig{}},
		{"whitespace only", &gateonv1.OtelConfig{ServiceName: "   "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveServiceName(tc.conf, noEnvVars); got != DefaultServiceName {
				t.Fatalf("ResolveServiceName() = %q, want %q", got, DefaultServiceName)
			}
		})
	}
}

// OTEL_SERVICE_NAME is the name the OpenTelemetry spec gives this setting, and
// an orchestrator setting it per replica must beat a value baked into a shared
// config file.
func TestEnvironmentBeatsConfig(t *testing.T) {
	got := ResolveServiceName(
		&gateonv1.OtelConfig{ServiceName: "from-config"},
		env(map[string]string{"OTEL_SERVICE_NAME": "from-env"}),
	)
	if got != "from-env" {
		t.Fatalf("ResolveServiceName() = %q, want the environment value", got)
	}
}

func TestBlankEnvironmentFallsBackToConfig(t *testing.T) {
	got := ResolveServiceName(
		&gateonv1.OtelConfig{ServiceName: "from-config"},
		env(map[string]string{"OTEL_SERVICE_NAME": "   "}),
	)
	if got != "from-config" {
		t.Fatalf("ResolveServiceName() = %q, want the config value", got)
	}
}

func TestNamesAreTrimmed(t *testing.T) {
	if got := ResolveServiceName(&gateonv1.OtelConfig{ServiceName: "  gw  "}, noEnvVars); got != "gw" {
		t.Errorf("ResolveServiceName() = %q, want it trimmed", got)
	}
}
