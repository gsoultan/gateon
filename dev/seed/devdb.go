// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	neturl "net/url"
	"path/filepath"
	"strings"

	"github.com/gsoultan/gateon/internal/db"
	"golang.org/x/crypto/bcrypt"
)

// errNotDevDatabase refuses to store a password the policy would refuse in a
// database that might be serving a real gateway.
var errNotDevDatabase = errors.New("refusing to store a password the policy refuses outside a dev database " +
	"(a SQLite file under dev/.data, or Postgres on 127.0.0.1/::1/localhost); " +
	"set GATEON_DEV_PASSWORD to one of at least 12 characters instead")

// devDataDir is the directory scripts/dev.sh keeps its state in. A SQLite file
// counts as a developer's only when it is inside one.
const devDataDir = "dev/.data"

// requireDevDatabase refuses any database that is not plainly a developer's.
// It looks at where the database is, never at what it contains: a production
// database copied to a laptop is the developer's problem, but a seed pointed at
// a production host by a mistyped flag is refused here.
func requireDevDatabase(dbURL string) error {
	if isDevDatabase(dbURL) {
		return nil
	}
	return fmt.Errorf("%w: got %q", errNotDevDatabase, redact(dbURL))
}

func isDevDatabase(dbURL string) bool {
	u := strings.TrimSpace(dbURL)
	lower := strings.ToLower(u)
	switch {
	case strings.HasPrefix(lower, "postgres://"), strings.HasPrefix(lower, "postgresql://"):
		return isLoopbackPostgres(u)
	case strings.Contains(u, "://") && !strings.HasPrefix(lower, "sqlite://"):
		return false
	}
	path := strings.TrimPrefix(strings.TrimPrefix(u, "sqlite:"), "//")
	path, _, _ = strings.Cut(path, "?")
	return isUnderDevData(path)
}

func isLoopbackPostgres(dbURL string) bool {
	parsed, err := neturl.Parse(dbURL)
	if err != nil {
		return false
	}
	// A DSN may also name its host as a query parameter, which libpq lets
	// override the authority. Any host= at all disqualifies it rather than
	// trying to decide which one wins.
	if parsed.Query().Has("host") || parsed.Query().Has("hostaddr") {
		return false
	}
	host := parsed.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isUnderDevData(path string) bool {
	if path == "" || path == ":memory:" {
		return false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	sep := string(filepath.Separator)
	marker := sep + filepath.FromSlash(devDataDir) + sep
	return strings.Contains(filepath.Clean(abs)+sep, marker) &&
		!strings.HasSuffix(filepath.Clean(abs)+sep, marker)
}

// redact drops a URL's password before it goes into an error message.
func redact(dbURL string) string {
	parsed, err := neturl.Parse(dbURL)
	if err != nil || parsed.User == nil {
		return dbURL
	}
	return parsed.Redacted()
}

// setPasswordHash stores password for username without the policy check every
// API applies. The schema is the one auth.NewManager just migrated.
func setPasswordHash(dbURL, username, password string) error {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	conn, dialect, err := db.Open(dbURL)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	res, err := conn.Exec(dialect.Rebind("UPDATE users SET password = ? WHERE username = ?"), string(hashed), username)
	if err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n != 1 {
		return fmt.Errorf("set password: %d accounts named %q", n, username)
	}
	return nil
}

// randomPassword is a password the policy accepts and nobody knows.
func randomPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random password: %w", err)
	}
	return hex.EncodeToString(b), nil
}
