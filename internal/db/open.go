package db

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

// Open opens a database connection from a URL-style string.
// Supported formats:
//   - sqlite:path or sqlite://path  -> SQLite (e.g. sqlite:gateon.db)
//   - postgres://user:pass@host:port/dbname?sslmode=disable
//   - mysql://user:pass@tcp(host:3306)/dbname
//   - mariadb://user:pass@tcp(host:3306)/dbname  (uses MySQL driver)
//
// For backward compatibility, a plain path like "gateon.db" is treated as sqlite:gateon.db.
func Open(url string) (*sql.DB, Dialect, error) {
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

	return db, Dialect{Driver: driver}, nil
}

func parseURL(url string) (driver, dsn string) {
	url = strings.TrimSpace(url)
	if url == "" {
		return "", ""
	}

	// Plain path -> SQLite (backward compat)
	if !strings.Contains(url, "://") && !strings.HasPrefix(url, "sqlite:") {
		if len(url) > 0 && url[0] != ':' {
			return DriverSQLite, url
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
		return DriverSQLite, path
	}

	// postgres:// or postgresql://
	if strings.HasPrefix(url, "postgres://") || strings.HasPrefix(url, "postgresql://") {
		return DriverPostgres, url
	}

	// mysql:// or mariadb:// (driver expects DSN without scheme)
	if strings.HasPrefix(url, "mysql://") {
		return DriverMySQL, strings.TrimPrefix(url, "mysql://")
	}
	if strings.HasPrefix(url, "mariadb://") {
		return DriverMySQL, strings.TrimPrefix(url, "mariadb://")
	}

	return "", ""
}
