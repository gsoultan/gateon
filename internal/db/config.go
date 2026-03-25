package db

import (
	"fmt"
	"net/url"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

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
