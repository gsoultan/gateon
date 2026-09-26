// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"errors"
	"fmt"
	"net/url"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ErrNoDatabase is Probe's answer when neither the url nor the config names a
// database it can build a DSN for.
var ErrNoDatabase = errors.New("missing database configuration")

// Probe proves a database named over the network can be opened: databaseURL
// wins over cfg, a SQLite one must be a plain file inside dataDir (see
// ConfineSQLite), and the connection is closed as soon as it answers.
//
// It is what the first-run wizard's connection test and Setup itself run, so
// the database an operator tested is judged by the same rules as the one they
// submit.
func Probe(databaseURL string, cfg *gateonv1.DatabaseConfig, dataDir string) error {
	dsn := databaseURL
	if dsn == "" {
		dsn = BuildURLFromConfig(cfg)
	}
	if dsn == "" {
		return ErrNoDatabase
	}
	if err := ConfineSQLite(dsn, dataDir); err != nil {
		return err
	}
	conn, _, err := Open(dsn)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	_ = conn.Close()
	return nil
}

// AuthDatabaseURL returns the database URL from AuthConfig.
// Prefers database_config (builds URL); else database_url; else sqlite_path.
func AuthDatabaseURL(auth *gateonv1.AuthConfig) string {
	if auth == nil {
		return "gateon.db"
	}
	if url := BuildURLFromConfig(auth.DatabaseConfig); url != "" {
		return url
	}
	if auth.DatabaseUrl != "" {
		return auth.DatabaseUrl
	}
	if auth.SqlitePath != "" {
		return auth.SqlitePath
	}
	return "gateon.db"
}

// AuditDatabaseURL returns the database URL used for audit/logging storage.
// Prefers the dedicated audit database (database_config, then database_url);
// when none is configured it falls back to the auth/management database.
func AuditDatabaseURL(audit *gateonv1.AuditConfig, auth *gateonv1.AuthConfig) string {
	if audit != nil {
		if url := BuildURLFromConfig(audit.DatabaseConfig); url != "" {
			return url
		}
		if audit.DatabaseUrl != "" {
			return audit.DatabaseUrl
		}
	}
	return AuthDatabaseURL(auth)
}

// BuildURLFromConfig builds a DSN from DatabaseConfig. Returns "" if cfg is nil or driver is sqlite with empty path.
func BuildURLFromConfig(cfg *gateonv1.DatabaseConfig) string {
	if cfg == nil || cfg.Driver == "" {
		return ""
	}
	switch cfg.Driver {
	case "sqlite":
		path := cfg.SqlitePath
		if path == "" {
			path = "gateon.db"
		}
		return path
	case "postgres", "postgresql":
		port := cfg.Port
		if port <= 0 {
			port = 5432
		}
		db := cfg.Database
		if db == "" {
			db = "gateon"
		}
		host := cfg.Host
		if host == "" {
			host = "127.0.0.1"
		}
		u := url.URL{
			Scheme: "postgres",
			Host:   fmt.Sprintf("%s:%d", host, port),
			Path:   "/" + db,
			User:   url.UserPassword(cfg.User, cfg.Password),
		}
		q := u.Query()
		if cfg.SslMode != "" {
			q.Set("sslmode", cfg.SslMode)
		} else {
			q.Set("sslmode", "disable")
		}
		u.RawQuery = q.Encode()
		return u.String()
	// Still builds a URL for an engine Open refuses, deliberately. Returning ""
	// here would surface as "invalid database URL", which tells an operator who
	// selected MySQL nothing about why. Building it lets the refusal in Open --
	// the one place that explains the engine was never supported -- be what they
	// actually see.
	case "mysql", "mariadb":
		port := cfg.Port
		if port <= 0 {
			port = 3306
		}
		host := cfg.Host
		if host == "" {
			host = "127.0.0.1"
		}
		db := cfg.Database
		if db == "" {
			db = "gateon"
		}
		user := url.QueryEscape(cfg.User)
		pass := url.QueryEscape(cfg.Password)
		return fmt.Sprintf("mysql://%s:%s@tcp(%s:%d)/%s", user, pass, host, port, db)
	default:
		return ""
	}
}
