// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package inits

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func InitGlobalConfig(globalFile string, globalReg *config.GlobalRegistry) *auth.Manager {
	activeTier := config.ResolveProfile()
	if os.Getenv("GATEON_PROFILE") != "" {
		logger.L.LogInfo("using active resource profile tier", "tier", activeTier, "source", "GATEON_PROFILE env")
	} else {
		logger.L.LogInfo("using active resource profile tier", "tier", activeTier, "source", "global config")
	}

	var authManager *auth.Manager
	// Only init auth and apply defaults when global.json exists (not first run)
	if !globalReg.ConfigFileExists() {
		return nil
	}
	if gc := globalReg.Get(context.Background()); gc != nil {
		if gc.Auth == nil || (gc.Auth.PasetoSecret == "" && db.AuthDatabaseURL(gc.Auth) == "gateon.db") {
			if gc.Auth == nil {
				gc.Auth = &gateonv1.AuthConfig{}
			}
			if gc.Auth.PasetoSecret == "" {
				gc.Auth.PasetoSecret = config.GenerateRandomSecret(32)
			}
			if !hasAuthDatabase(gc.Auth) {
				setDefaultSqliteConfig(gc.Auth)
			}
			if err := globalReg.Update(context.Background(), gc); err != nil {
				logger.L.LogError("failed to persist bootstrap auth defaults", "error", err)
			}
		}
		if gc.Auth == nil {
			gc.Auth = &gateonv1.AuthConfig{}
		}
		if !hasAuthDatabase(gc.Auth) {
			setDefaultSqliteConfig(gc.Auth)
		}
		if gc.Auth.PasetoSecret == "" {
			gc.Auth.PasetoSecret = config.GenerateRandomSecret(32)
		}
		databaseURL := db.AuthDatabaseURL(gc.Auth)
		if databaseURL != "" {
			var err error
			authManager, err = auth.NewManager(databaseURL, gc.Auth.PasetoSecret, logger.Default())
			if err != nil {
				logger.Fatal("failed to initialize auth manager", "error", err)
			}
		}
		applyGlobalEnv(gc)
	}
	return authManager
}

// applyGlobalEnv publishes the parts of the global config that downstream
// packages read through the environment.
//
// Every value here is written only when the config actually carries one. That
// is not a micro-optimisation: setEnv on an empty string does not clear the
// variable, it sets it to "", which destroys whatever the operator exported
// before starting the process. Four of these -- enabled, email, the two TLS
// versions and the client auth type -- used to be written unconditionally while
// the six around them were guarded, so a global.json with an empty tls block
// silently wiped GATEON_TLS_EMAIL and friends out of a deployment that had set
// them deliberately.
//
// Enabled is the exception and stays unconditional: false is a real value for a
// bool, and omitting it would make "TLS off in config" indistinguishable from
// "config says nothing", which is the ambiguity the rest of this function
// exists to avoid.
// warnDisabledByUpgrade reports config that used to work and no longer does.
//
// redis.enabled and otel.enabled were read by nothing before 2026-09-01, so an
// address or endpoint alone was enough to connect. Now the flag gates it, which
// silently disconnects a hand-written config that set one without the other.
// proto3 cannot tell an unset bool from an explicit false, so nothing can
// migrate this automatically -- but the exact broken shape is detectable, and an
// operator who reads one line at startup is better served than one who has to
// find it in release notes after the fact.
// It returns the messages rather than logging them so a test can assert that
// the right config shape produces a warning. Asserting that the function does
// not panic would pass whether or not it ever warned.
func disabledByUpgradeWarnings(gc *gateonv1.GlobalConfig) []string {
	if gc == nil {
		return nil
	}
	var out []string
	if gc.Redis != nil && gc.Redis.Addr != "" && !gc.Redis.Enabled {
		out = append(out, "redis.addr is set but redis.enabled is false, so Redis will NOT be used. "+
			"Before this version the address alone was enough. Set redis.enabled = true to restore it, "+
			"or clear redis.addr to silence this.")
	}
	if gc.Otel != nil && gc.Otel.Endpoint != "" && !gc.Otel.Enabled {
		out = append(out, "otel.endpoint is set but otel.enabled is false, so traces will NOT be exported. "+
			"Before this version the endpoint alone was enough. Set otel.enabled = true to restore it, "+
			"or clear otel.endpoint to silence this.")
	}
	return out
}

func warnDisabledByUpgrade(gc *gateonv1.GlobalConfig) {
	for _, w := range disabledByUpgradeWarnings(gc) {
		logger.L.LogWarn(w)
	}
}

func applyGlobalEnv(gc *gateonv1.GlobalConfig) {
	if gc == nil {
		return
	}
	warnDisabledByUpgrade(gc)
	// otel.enabled gates the endpoint. It was read by nothing, so tracing
	// exported whenever an endpoint was present and the dashboard toggle could
	// not stop it. OTEL_EXPORTER_OTLP_ENDPOINT set directly in the environment
	// is untouched by this and still exports on its own.
	if gc.Otel != nil && gc.Otel.Enabled && gc.Otel.Endpoint != "" {
		setEnv("OTEL_EXPORTER_OTLP_ENDPOINT", gc.Otel.Endpoint)
	}
	// redis.enabled gates the address here too, and this is the gate that
	// actually matters. Without it the config address is copied into REDIS_ADDR,
	// and the resolver treats that variable as an explicit instruction exempt
	// from the flag -- so the toggle would have been defeated by the very
	// mechanism that carries its value.
	if gc.Redis != nil && gc.Redis.Enabled && gc.Redis.Addr != "" {
		setEnv("REDIS_ADDR", gc.Redis.Addr)
	}
	if gc.Tls == nil {
		return
	}
	setEnv("GATEON_TLS_ENABLED", strconv.FormatBool(gc.Tls.Enabled))
	setEnvIfSet("GATEON_TLS_EMAIL", gc.Tls.Email)
	setEnvIfSet("GATEON_TLS_MIN_VERSION", gc.Tls.MinTlsVersion)
	setEnvIfSet("GATEON_TLS_MAX_VERSION", gc.Tls.MaxTlsVersion)
	setEnvIfSet("GATEON_TLS_CLIENT_AUTH_TYPE", gc.Tls.ClientAuthType)
	if len(gc.Tls.Domains) > 0 {
		setEnv("GATEON_TLS_DOMAINS", strings.Join(gc.Tls.Domains, ","))
	}
	if len(gc.Tls.CipherSuites) > 0 {
		setEnv("GATEON_TLS_CIPHER_SUITES", strings.Join(gc.Tls.CipherSuites, ","))
	}
}

// setEnvIfSet writes value only when the config supplies one, leaving any
// operator-supplied environment variable intact when it does not.
func setEnvIfSet(key, value string) {
	if value == "" {
		return
	}
	setEnv(key, value)
}

// setEnv sets an environment variable and logs (rather than silently ignoring)
// any failure so a misconfigured environment surfaces in the logs.
func setEnv(key, value string) {
	if err := os.Setenv(key, value); err != nil {
		logger.L.LogError("failed to set environment variable", "error", err, "key", key)
	}
}

// hasAuthDatabase returns true if auth has any database configuration.
func hasAuthDatabase(auth *gateonv1.AuthConfig) bool {
	if auth == nil {
		return false
	}
	if auth.DatabaseUrl != "" {
		return true
	}
	if auth.DatabaseConfig != nil && auth.DatabaseConfig.Driver != "" {
		return true
	}
	if auth.SqlitePath != "" {
		return true
	}
	return false
}

// setDefaultSqliteConfig sets database_config to default SQLite (gateon.db).
func setDefaultSqliteConfig(auth *gateonv1.AuthConfig) {
	if auth == nil {
		return
	}
	if auth.DatabaseConfig == nil {
		auth.DatabaseConfig = &gateonv1.DatabaseConfig{}
	}
	auth.DatabaseConfig.Driver = "sqlite"
	auth.DatabaseConfig.SqlitePath = "gateon.db"
}
