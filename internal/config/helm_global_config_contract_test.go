// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config_test

import (
	"encoding/json"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The Helm chart writes global.json, and gateon parses it with encoding/json
// against the generated protobuf structs — so the keys are the `json:` struct
// tags, which are snake_case. That is not cosmetic here: this project has
// already shipped a bug where the dashboard wrote camelCase and Go read
// snake_case, leaving 73 middleware settings inert with nothing reporting an
// error.
//
// The fixture below is what `helm template` emits for
// charts/gateon with externalDatabase.enabled and redis.enabled. If a proto
// field is renamed, or its json tag changes, this fails — instead of the chart
// quietly deploying replicas that all fall back to SQLite while appearing
// configured.
//
// Keep it in step with charts/gateon/templates/_helpers.tpl (gateon.globalConfig).
const helmRenderedGlobalConfig = `{
  "auth": {
    "database_config": {
      "database": "gateon",
      "driver": "postgres",
      "host": "pg.svc",
      "password": "s3cret",
      "port": 5432,
      "ssl_mode": "require",
      "user": "gateon"
    }
  },
  "redis": {
    "addr": "redis:6379",
    "db": 0,
    "enabled": true
  }
}`

func TestHelmRenderedGlobalConfigParsesIntoEveryFieldItSets(t *testing.T) {
	var cfg gateonv1.GlobalConfig
	if err := json.Unmarshal([]byte(helmRenderedGlobalConfig), &cfg); err != nil {
		t.Fatalf("the chart's global.json does not parse: %v", err)
	}

	if cfg.Auth == nil || cfg.Auth.DatabaseConfig == nil {
		t.Fatal("auth.database_config did not survive parsing; every replica would fall back to SQLite")
	}
	db := cfg.Auth.DatabaseConfig
	for _, tc := range []struct{ name, got, want string }{
		{"driver", db.Driver, "postgres"},
		{"host", db.Host, "pg.svc"},
		{"user", db.User, "gateon"},
		{"password", db.Password, "s3cret"},
		{"database", db.Database, "gateon"},
		{"ssl_mode", db.SslMode, "require"},
	} {
		if tc.got != tc.want {
			t.Errorf("auth.database_config.%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	if db.Port != 5432 {
		t.Errorf("auth.database_config.port = %d, want 5432", db.Port)
	}

	if cfg.Redis == nil {
		t.Fatal("redis block did not survive parsing")
	}
	// enabled is what actually gates the subsystem: an addr with no flag is a
	// config that connects to nothing. See doc/upgrading.md under v2.6.0.
	if !cfg.Redis.GetEnabled() {
		t.Error("redis.enabled did not parse; the address alone does not turn Redis on from a config file")
	}
	if cfg.Redis.GetAddr() != "redis:6379" {
		t.Errorf("redis.addr = %q, want redis:6379", cfg.Redis.GetAddr())
	}
}

// The chart also renders entrypoints.json, which is what makes the ports the
// Service publishes ports the gateway actually binds. If this shape drifts, the
// Service forwards to a container that is not listening and every request times
// out with nothing in the log explaining why.
//
// Matches charts/gateon/templates/_helpers.tpl (gateon.entrypointsJSON) and the
// shape in dev/entrypoints.json.
const helmRenderedEntrypoints = `[
  {
    "address": ":8000",
    "id": "web",
    "name": "web",
    "protocol": 0,
    "type": 0
  }
]`

func TestHelmRenderedEntrypointsParse(t *testing.T) {
	var eps []*gateonv1.EntryPoint
	if err := json.Unmarshal([]byte(helmRenderedEntrypoints), &eps); err != nil {
		t.Fatalf("the chart's entrypoints.json does not parse: %v", err)
	}
	if len(eps) != 1 {
		t.Fatalf("got %d entrypoints, want 1", len(eps))
	}
	ep := eps[0]
	if ep.GetId() != "web" {
		t.Errorf("id = %q, want web", ep.GetId())
	}
	// The address is what the listener binds. An empty one here would mean the
	// chart published a Service port to nothing.
	if ep.GetAddress() != ":8000" {
		t.Errorf("address = %q, want :8000", ep.GetAddress())
	}
	if ep.GetType() != gateonv1.EntryPoint_HTTP {
		t.Errorf("type = %v, want HTTP", ep.GetType())
	}
	if ep.GetProtocol() != gateonv1.EntryPoint_TCP_PROTO {
		t.Errorf("protocol = %v, want TCP_PROTO", ep.GetProtocol())
	}
}
