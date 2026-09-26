// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

// ErrUnsupportedEngine is returned for a database URL naming an engine gateon
// cannot serve. It is a distinct error so a caller can tell a configuration
// mistake from a database that is merely unreachable.
var ErrUnsupportedEngine = errors.New("unsupported database engine")

// refusedSchemes are engines this package advertised without ever supporting.
//
// MySQL and MariaDB were accepted by parseURL, and nearly every migration
// carried a MySQL arm, but none of it ever ran: migration 2 puts two TEXT
// columns in a PRIMARY KEY, which MySQL rejects outright, so no MySQL database
// has ever reached migration 3. Those arms were not merely untested, they were
// written in a dialect MySQL does not accept -- 43 of 62 migrations failed on a
// real server even with migration 2 repaired, most of them on ADD COLUMN IF NOT
// EXISTS and DEFAULT values on TEXT columns, neither of which MySQL supports.
// They have since been deleted, so this map is now the only thing standing
// between an operator and a database that cannot build its own schema.
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
	if driver == DriverSQLite {
		if err := restrictSQLiteFiles(dsn); err != nil {
			return nil, Dialect{}, err
		}
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
		return DriverPostgres, withPostgresSessionZone(url)
	}

	return "", ""
}

// postgresSessionZone is the TimeZone every Postgres session runs in.
//
// Several columns are TIMESTAMP without time zone and are written with
// CURRENT_TIMESTAMP, which Postgres renders in the session's zone -- the
// server's configured default unless the client names one. The code that reads
// them compares against UTC wall clocks computed in Go (mitigationCutoff says
// so), which is what SQLite's CURRENT_TIMESTAMP produces. On a server installed
// in any other zone every such comparison moved by the zone's offset: behind
// UTC a fingerprint block was expired the moment it was written and never
// stopped a request, ahead of UTC a one-hour block lasted hours longer.
const postgresSessionZone = "UTC"

// withPostgresSessionZone sets the session TimeZone as a startup parameter,
// replacing any spelling of it the DSN already carried, because what the
// schema's timestamps mean depends on it. A DSN that does not parse is
// returned unchanged for sql.Open to reject, and is never echoed.
func withPostgresSessionZone(dsn string) string {
	u, err := neturl.Parse(dsn)
	if err != nil {
		return dsn
	}
	q := u.Query()
	for key := range q {
		if strings.EqualFold(key, "timezone") {
			q.Del(key)
		}
	}
	q.Set("timezone", postgresSessionZone)
	u.RawQuery = q.Encode()
	return u.String()
}

// sqliteFileMode is owner-only, the mode every other file gateon keeps secrets
// in already uses (the config registries, uploaded keys, the WAF audit log).
const sqliteFileMode fs.FileMode = 0o600

// sqliteSidecars are the files SQLite keeps beside a database. They carry the
// same pages as the database itself, and SQLite creates them with the database
// file's mode -- so a loose -wal left by an unclean shutdown stays loose.
var sqliteSidecars = []string{"-wal", "-shm", "-journal"}

// restrictSQLiteFiles makes the SQLite database and its sidecars owner-only
// before the driver opens them.
//
// Left to itself SQLite creates the file 0644 and leaves the rest to the umask,
// which is 022 under systemd, Docker and a login shell alike. That database
// holds every middleware's configuration in plain JSON -- JWT and HMAC
// secrets, OIDC client secrets, API keys -- along with password hashes and the
// audit trail, and the packaged unit's state directory was 0755. Any local
// account could read it.
//
// A new file is created 0600 here so SQLite never gets to choose; an existing
// one, from an earlier version, has its group and other bits removed. A file
// gateon does not own cannot be chmodded; that is somebody's deliberate
// arrangement, so it is reported rather than treated as fatal.
func restrictSQLiteFiles(dsn string) error {
	path, ok := sqliteFilePath(dsn)
	if !ok {
		return nil
	}
	// #nosec G304 -- path is the operator's configured database, the file
	// sql.Open is about to open anyway; this only decides the mode it gets.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, sqliteFileMode)
	if err == nil {
		return f.Close()
	}
	if !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("create sqlite database %s: %w", path, err)
	}
	for _, p := range append([]string{path}, sidecarPaths(path)...) {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm()&^sqliteFileMode == 0 {
			continue
		}
		if err := os.Chmod(p, info.Mode().Perm()&sqliteFileMode); err != nil {
			logger.L.LogWarn("sqlite file is readable by other accounts and could not be restricted",
				"path", p, "mode", fmt.Sprintf("%#o", info.Mode().Perm()), "error", err)
		}
	}
	return nil
}

// ErrSQLiteNotConfined refuses a SQLite database named over the network that
// is not a plain file path inside the data directory.
var ErrSQLiteNotConfined = errors.New("a SQLite database set up from the network must be a plain file path inside the data directory")

// ConfineSQLite refuses a SQLite database url that is not a plain file path
// inside dir.
//
// It is for a database named over the network: the first-run setup wizard,
// which opens the caller's database before anyone has authenticated. Opening
// a SQLite database creates its file when it is missing, and
// restrictSQLiteFiles strips group and other permissions from one that
// exists, so the path decided which file on the host the gateway created or
// chmodded -- any file it could write, /etc/passwd for a gateway running as
// root.
//
// The rest of a url reaches further than its path, so it is refused rather
// than checked. Every _pragma in a query string runs as SQL when the database
// opens, and a percent-encoded semicolon lets one carry an ATTACH, which
// creates a database wherever it names. SQLite percent-decodes a file: URI
// after any check on the string, so "..%2F" climbs out of a directory the
// string never left. And C reads a name only as far as its first NUL, which
// need not be as far as the path checked here. A wizard needs none of them.
//
// A relative path is resolved the way the opener resolves it, against the
// working directory, which the packaged unit and image set to the data
// directory. A url for another engine is not its concern.
func ConfineSQLite(url, dir string) error {
	driver, dsn := parseURL(url)
	if driver != DriverSQLite {
		return nil
	}
	path, _, _ := strings.Cut(dsn, "?")
	if strings.ContainsAny(url, "?\x00") || (len(path) >= 5 && strings.EqualFold(path[:5], "file:")) {
		return ErrSQLiteNotConfined
	}
	if path == ":memory:" {
		return nil
	}
	file, err := filepath.Abs(path)
	if err != nil {
		return ErrSQLiteNotConfined
	}
	base, err := filepath.Abs(dir)
	if err != nil {
		return ErrSQLiteNotConfined
	}
	rel, err := filepath.Rel(base, file)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w (%s)", ErrSQLiteNotConfined, base)
	}
	return nil
}

func sidecarPaths(path string) []string {
	out := make([]string, 0, len(sqliteSidecars))
	for _, s := range sqliteSidecars {
		out = append(out, path+s)
	}
	return out
}

// sqliteFilePath extracts the filesystem path from a DSN produced by parseURL.
// It declines in-memory databases, which have no file, and SQLite URI
// filenames ("file:..."), whose query can make them read-only or in-memory
// and which no documented configuration produces.
func sqliteFilePath(dsn string) (string, bool) {
	path, _, _ := strings.Cut(dsn, "?")
	if path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") {
		return "", false
	}
	return path, true
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
