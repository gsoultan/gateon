// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// defaultSQLiteFile is the management database when the config names none.
const defaultSQLiteFile = "gateon.db"

// AuthDatabaseURL returns the database URL from AuthConfig.
// Prefers database_config (builds URL); else database_url; else sqlite_path.
// A relative SQLite path is taken inside config.DataDir (see ResolveSQLitePath).
func AuthDatabaseURL(auth *gateonv1.AuthConfig) string {
	return ResolveSQLitePath(authDatabaseURL(auth), config.DataDir())
}

func authDatabaseURL(auth *gateonv1.AuthConfig) string {
	if auth == nil {
		return defaultSQLiteFile
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
	return defaultSQLiteFile
}

// ResolveSQLitePath returns databaseURL with a relative SQLite file path made
// relative to dir instead of to the working directory. Anything else -- a
// server URL, an absolute path, ":memory:", a "file:" URI or a path carrying
// its own query -- comes back unchanged.
//
// A relative path used to be opened against whatever directory the process
// started in. The packaged unit sets WorkingDirectory to the data directory, so
// it happened to work there; the tarball, a hand-run binary, a container whose
// WORKDIR differed, or a custom unit got a fresh, empty gateon.db (and a fresh
// trace store beside it), and first-run setup reopened on a configured gateway
// with every route and user apparently gone. The data directory is the answer
// the rest of the gateway already gives to "where does state live", so it is
// the answer here. Where config.DataDir has no better answer it returns ".",
// which leaves a development checkout exactly where it was.
func ResolveSQLitePath(databaseURL, dir string) string {
	prefix, path, ok := splitSQLite(strings.TrimSpace(databaseURL))
	if !ok || !relativeSQLiteFile(path) {
		return databaseURL
	}
	return prefix + filepath.Join(dir, path)
}

// SQLiteFile is the file a SQLite database URL opens, and false for any other
// engine and for a database that is not a plain file (":memory:", a "file:"
// URI).
func SQLiteFile(databaseURL string) (string, bool) {
	_, path, ok := splitSQLite(strings.TrimSpace(databaseURL))
	if !ok || path == "" || strings.HasPrefix(path, ":") || strings.ContainsAny(path, "?\x00") {
		return "", false
	}
	if len(path) >= 5 && strings.EqualFold(path[:5], "file:") {
		return "", false
	}
	return path, true
}

// splitSQLite separates a SQLite URL into its scheme prefix ("", "sqlite:" or
// "sqlite://") and its path. ok is false for any other engine.
func splitSQLite(u string) (prefix, path string, ok bool) {
	for _, p := range []string{"sqlite://", "sqlite:"} {
		if rest, found := strings.CutPrefix(u, p); found {
			return p, rest, true
		}
	}
	if strings.Contains(u, "://") {
		return "", "", false
	}
	return "", u, true
}

// relativeSQLiteFile reports whether path is a plain relative file name that
// ResolveSQLitePath should move into the data directory.
func relativeSQLiteFile(path string) bool {
	switch {
	case path == "", strings.HasPrefix(path, ":"), filepath.IsAbs(path):
		return false
	case strings.ContainsAny(path, "?\x00"):
		return false
	case len(path) >= 5 && strings.EqualFold(path[:5], "file:"):
		return false
	}
	return true
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
			return ResolveSQLitePath(audit.DatabaseUrl, config.DataDir())
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
			path = defaultSQLiteFile
		}
		return ResolveSQLitePath(path, config.DataDir())
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
