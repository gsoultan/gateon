// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package inits

import (
	"os"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// applyGlobalEnv is how config values reach the subsystems that read the
// environment, so it is where the enabled flags have to be honoured. Gating only
// the consumer would not work for Redis: the address is copied into REDIS_ADDR
// here, and the resolver treats that variable as an explicit instruction exempt
// from the flag, so an ungated copy would defeat the toggle it carries.
func TestEnabledFlagsGateTheEnvironmentBridge(t *testing.T) {
	for _, tc := range []struct {
		name      string
		gc        *gateonv1.GlobalConfig
		wantOtel  string
		wantRedis string
	}{
		{
			name: "both enabled",
			gc: &gateonv1.GlobalConfig{
				Otel:  &gateonv1.OtelConfig{Enabled: true, Endpoint: "otel:4318"},
				Redis: &gateonv1.RedisConfig{Enabled: true, Addr: "redis:6379"},
			},
			wantOtel: "otel:4318", wantRedis: "redis:6379",
		},
		{
			name: "endpoints set but flags unset",
			gc: &gateonv1.GlobalConfig{
				Otel:  &gateonv1.OtelConfig{Endpoint: "otel:4318"},
				Redis: &gateonv1.RedisConfig{Addr: "redis:6379"},
			},
			wantOtel: "", wantRedis: "",
		},
		{
			name: "explicitly disabled",
			gc: &gateonv1.GlobalConfig{
				Otel:  &gateonv1.OtelConfig{Enabled: false, Endpoint: "otel:4318"},
				Redis: &gateonv1.RedisConfig{Enabled: false, Addr: "redis:6379"},
			},
			wantOtel: "", wantRedis: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv registers restoration, so the process env is left as found.
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
			t.Setenv("REDIS_ADDR", "")
			_ = os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
			_ = os.Unsetenv("REDIS_ADDR")

			applyGlobalEnv(tc.gc)

			if got := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); got != tc.wantOtel {
				t.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT = %q, want %q", got, tc.wantOtel)
			}
			if got := os.Getenv("REDIS_ADDR"); got != tc.wantRedis {
				t.Errorf("REDIS_ADDR = %q, want %q", got, tc.wantRedis)
			}
		})
	}
}

// TestUpgradeWarningFiresForConfigThatUsedToWork checks the message is actually
// produced, not merely that the function survives. redis.enabled and
// otel.enabled were read by nothing before this version, so an address alone
// connected; now the flag gates it, and the exact broken shape is detectable.
func TestUpgradeWarningFiresForConfigThatUsedToWork(t *testing.T) {
	for _, tc := range []struct {
		name  string
		gc    *gateonv1.GlobalConfig
		want  int
		match string
	}{
		{
			name:  "redis address without the flag",
			gc:    &gateonv1.GlobalConfig{Redis: &gateonv1.RedisConfig{Addr: "redis:6379"}},
			want:  1,
			match: "redis.enabled",
		},
		{
			name:  "otel endpoint without the flag",
			gc:    &gateonv1.GlobalConfig{Otel: &gateonv1.OtelConfig{Endpoint: "otel:4318"}},
			want:  1,
			match: "otel.enabled",
		},
		{
			name: "both broken",
			gc: &gateonv1.GlobalConfig{
				Redis: &gateonv1.RedisConfig{Addr: "redis:6379"},
				Otel:  &gateonv1.OtelConfig{Endpoint: "otel:4318"},
			},
			want: 2,
		},
		{
			name: "both enabled: silent",
			gc: &gateonv1.GlobalConfig{
				Redis: &gateonv1.RedisConfig{Enabled: true, Addr: "redis:6379"},
				Otel:  &gateonv1.OtelConfig{Enabled: true, Endpoint: "otel:4318"},
			},
			want: 0,
		},
		{
			name: "nothing configured: silent",
			gc:   &gateonv1.GlobalConfig{Redis: &gateonv1.RedisConfig{}, Otel: &gateonv1.OtelConfig{}},
			want: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := disabledByUpgradeWarnings(tc.gc)
			if len(got) != tc.want {
				t.Fatalf("got %d warnings %v, want %d", len(got), got, tc.want)
			}
			if tc.match != "" && !strings.Contains(got[0], tc.match) {
				t.Errorf("warning %q does not name %q, so it does not say how to fix it", got[0], tc.match)
			}
		})
	}
}

// Runs during startup before anything else exists, so no shape may panic.
func TestUpgradeWarningToleratesEmptyConfig(t *testing.T) {
	if got := disabledByUpgradeWarnings(nil); got != nil {
		t.Errorf("nil config produced %v", got)
	}
	warnDisabledByUpgrade(&gateonv1.GlobalConfig{})
}
