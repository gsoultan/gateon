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
func applyGlobalEnv(gc *gateonv1.GlobalConfig) {
	if gc == nil {
		return
	}
	if gc.Otel != nil && gc.Otel.Endpoint != "" {
		setEnv("OTEL_EXPORTER_OTLP_ENDPOINT", gc.Otel.Endpoint)
	}
	if gc.Redis != nil && gc.Redis.Addr != "" {
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
