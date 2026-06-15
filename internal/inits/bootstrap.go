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
		if gc.Otel != nil && gc.Otel.Endpoint != "" {
			setEnv("OTEL_EXPORTER_OTLP_ENDPOINT", gc.Otel.Endpoint)
		}
		if gc.Redis != nil && gc.Redis.Addr != "" {
			setEnv("REDIS_ADDR", gc.Redis.Addr)
		}
		if gc.Tls != nil {
			setEnv("GATEON_TLS_ENABLED", strconv.FormatBool(gc.Tls.Enabled))
			setEnv("GATEON_TLS_EMAIL", gc.Tls.Email)
			if len(gc.Tls.Domains) > 0 {
				setEnv("GATEON_TLS_DOMAINS", strings.Join(gc.Tls.Domains, ","))
			}
			setEnv("GATEON_TLS_MIN_VERSION", gc.Tls.MinTlsVersion)
			setEnv("GATEON_TLS_MAX_VERSION", gc.Tls.MaxTlsVersion)
			setEnv("GATEON_TLS_CLIENT_AUTH_TYPE", gc.Tls.ClientAuthType)
			if len(gc.Tls.CipherSuites) > 0 {
				setEnv("GATEON_TLS_CIPHER_SUITES", strings.Join(gc.Tls.CipherSuites, ","))
			}
		}
	}
	return authManager
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
