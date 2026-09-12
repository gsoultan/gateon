// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

// ErrUnsupportedEngine is returned for a database URL naming an engine gateon
// cannot serve. It is a distinct error so a caller can tell a configuration
// mistake from a database that is merely unreachable.
var ErrUnsupportedEngine = errors.New("unsupported database engine")

// refusedSchemes are engines this package advertised without ever supporting.
//
// MySQL and MariaDB were accepted by parseURL, and most migrations carry a
// DriverMySQL branch, but none of it has ever run: migration 2 puts two TEXT
// columns in a PRIMARY KEY, which MySQL rejects outright, so no MySQL database
// has ever reached migration 3. The branches below it are not merely untested,
// they are written in a dialect MySQL does not accept -- 43 of 62 migrations
// fail on a real server even with migration 2 repaired, most of them on
// ADD COLUMN IF NOT EXISTS and DEFAULT values on TEXT columns, neither of which
// MySQL supports.
//
// Accepting the DSN and failing at the second migration is the worst of the
// available behaviours: it happens at startup, after the operator has committed
// to the engine. Refusing the URL says the same thing at the point where it is
// still cheap to act on.
var refusedSchemes = map[string]string{
	"mysql":   "MySQL",
	"mariadb": "MariaDB",
}

// Open opens a database connection from a URL-style string.
// Supported formats:
//   - sqlite:path or sqlite://path  -> SQLite (e.g. sqlite:gateon.db)
//   - postgres://user:pass@host:port/dbname?sslmode=disable
//
// For backward compatibility, a plain path like "gateon.db" is treated as sqlite:gateon.db.
func Open(url string) (*sql.DB, Dialect, error) {
	if scheme, name := refusedEngine(url); name != "" {
		return nil, Dialect{}, fmt.Errorf(
			"%w: %s (%s://). gateon supports sqlite and postgres. %s was accepted by "+
				"earlier versions but never worked -- the schema has never been able to "+
				"build on it -- so there is no data to migrate and no version to go back to",
			ErrUnsupportedEngine, name, scheme, name)
	}

	driver, dsn := parseURL(url)
	if driver == "" || dsn == "" {
		return nil, Dialect{}, fmt.Errorf("invalid database URL: %q", url)
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, Dialect{}, fmt.Errorf("open %s: %w", driver, err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, Dialect{}, fmt.Errorf("ping %s: %w", driver, err)
	}

	// Configure connection pool for production resilience.
	// Defaults are tuned by resource tier (minimal: 5, standard: 25, enterprise: 100).
	td := config.CurrentTierDefaults()
	db.SetMaxOpenConns(td.DBMaxOpenConns)
	db.SetMaxIdleConns(td.DBMaxIdleConns)
	db.SetConnMaxLifetime(5 * time.Minute)

	return db, Dialect{Driver: driver}, nil
}

func parseURL(url string) (driver, dsn string) {
	url = strings.TrimSpace(url)
	if url == "" {
		return "", ""
	}

	// Default pragmas for modernc.org/sqlite to ensure production performance and concurrency.
	sqlitePragmas := "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"

	// Plain path -> SQLite (backward compat)
	if !strings.Contains(url, "://") && !strings.HasPrefix(url, "sqlite:") {
		if len(url) > 0 && url[0] != ':' {
			return DriverSQLite, url + sqlitePragmas
		}
		return "", ""
	}

	// sqlite:path or sqlite://path
	if strings.HasPrefix(url, "sqlite:") {
		path := strings.TrimPrefix(url, "sqlite:")
		path = strings.TrimPrefix(path, "//")
		if path == "" {
			path = "gateon.db"
		}
		if !strings.Contains(path, "?") {
			path += sqlitePragmas
		}
		return DriverSQLite, path
	}

	// postgres:// or postgresql://
	if strings.HasPrefix(url, "postgres://") || strings.HasPrefix(url, "postgresql://") {
		return DriverPostgres, url
	}

	return "", ""
}

// refusedEngine reports the scheme and display name when url names an engine
// gateon refuses, matching on the scheme only so a DSN is never logged back.
func refusedEngine(url string) (scheme, name string) {
	trimmed := strings.TrimSpace(url)
	idx := strings.Index(trimmed, "://")
	if idx <= 0 {
		return "", ""
	}
	got := strings.ToLower(trimmed[:idx])
	if display, ok := refusedSchemes[got]; ok {
		return got, display
	}
	return "", ""
}
