// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package inits

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
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
		if gc.Auth == nil || (gc.Auth.PasetoSecret == "" && db.AuthDatabaseURL(gc.Auth) == db.AuthDatabaseURL(nil)) {
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
		authManager = openAuthManager(gc.Auth)
		applyGlobalEnv(gc)
	}
	return authManager
}

// openAuthManager opens the user database a configured gateway names, and
// refuses to start one that was set up and has lost it.
func openAuthManager(a *gateonv1.AuthConfig) *auth.Manager {
	databaseURL := db.AuthDatabaseURL(a)
	if err := setUpDatabaseMissing(a, databaseURL); err != nil {
		logger.Fatal(err.Error())
	}
	m, err := auth.NewManager(databaseURL, a.GetPasetoSecret(), logger.Default())
	if err != nil {
		logger.Fatal("failed to initialize auth manager", "error", err)
	}
	if err := setUpWithoutAdministrator(a, m); err != nil {
		_ = m.Close()
		logger.Fatal(err.Error())
	}
	reconcileSecondFactors(m)
	return m
}

// refusedReopen is what both refusals below end with: what the operator can do.
const refusedReopen = "Refusing to start: going on would reopen first-run setup on a configured gateway, " +
	"to whoever reaches the management port first. Restore the database from a backup " +
	"(doc/backup-restore.md), or check GATEON_DATA_DIR and the configured database; to set this " +
	"gateway up from scratch, move global.json aside."

// setUpDatabaseMissing refuses a gateway that was set up -- auth.enabled is
// what setup writes -- whose SQLite user database file is not there.
//
// Opening it would have created it: an empty database, so no administrator, so
// setup reopened with every route and user apparently gone, and /readyz said
// ready. A data directory that is not mounted, a different working directory,
// a restore that missed a file -- each of those looked like a first run.
func setUpDatabaseMissing(a *gateonv1.AuthConfig, databaseURL string) error {
	if !a.GetEnabled() {
		return nil
	}
	file, ok := db.SQLiteFile(databaseURL)
	if !ok {
		return nil
	}
	if _, err := os.Stat(file); !errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("the user database %s does not exist, but global.json says this gateway was set up "+
		"(auth.enabled is true). %s", file, refusedReopen)
}

// setupState is the part of auth.Manager setUpWithoutAdministrator reads.
type setupState interface{ IsSetupDone() bool }

// setUpWithoutAdministrator refuses a gateway that was set up whose user
// database opened and holds no administrator: a Postgres database recreated
// empty, or a SQLite file replaced by an empty one. The same reopening as a
// missing file, by a different road.
func setUpWithoutAdministrator(a *gateonv1.AuthConfig, m setupState) error {
	if !a.GetEnabled() || m.IsSetupDone() {
		return nil
	}
	return fmt.Errorf("the user database has no administrator, but global.json says this gateway was set up "+
		"(auth.enabled is true). %s", refusedReopen)
}

// previousSessionKeyEnv names the session key that a key change replaced, so
// the second factors still encrypted under it can be moved to the new one. It
// only ever decrypts second factors: see auth.Manager.ReconcileSecondFactors.
const previousSessionKeyEnv = "GATEON_PREVIOUS_SESSION_KEY"

// reconcileSecondFactors checks at startup that every stored second factor
// decrypts under the session key in force, and moves those encrypted under the
// previous key when previousSessionKeyEnv names it. A key changed without the
// dashboard's rotation used to lock every 2FA account out, and said nothing.
func reconcileSecondFactors(m *auth.Manager) {
	report, err := m.ReconcileSecondFactors(os.Getenv(previousSessionKeyEnv))
	if err != nil {
		logger.L.LogError("could not check the stored second factors against the session key", "error", err)
		return
	}
	if report.Moved > 0 {
		logger.L.LogInfo("stored second factors re-encrypted under the session key", "count", report.Moved)
	}
	if report.Unreadable > 0 {
		logger.L.LogError("stored second factors do not decrypt under the session key, so those accounts cannot "+
			"complete a 2FA sign-in: the key was changed without the dashboard's rotation. Set "+
			previousSessionKeyEnv+" to the previous key and restart, or have those accounts enrol again",
			"count", report.Unreadable)
	}
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
