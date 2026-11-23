// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/config"
)

// PostgresDumpSuffix ends the name of the dump taken before a newer gateway
// migrates a PostgreSQL database (ADR 0105). One slot per database, like the
// SQLite copy: the next migrating upgrade replaces it.
const PostgresDumpSuffix = ".pre-upgrade.dump"

const (
	// pgDump is the PostgreSQL client program that writes the dump.
	pgDump = "pg_dump"
	// postgresDumpTimeout bounds one dump. It is under the fifteen minutes
	// the upgrade helper waits for a gateway that says it is backing up, so a
	// dump that hangs ends as a refused migration and not as a gateway the
	// helper gave up on with the migration still to come.
	postgresDumpTimeout = 12 * time.Minute
	// maxDumpStderr bounds how much of pg_dump's complaint is kept.
	maxDumpStderr = 4 << 10
	dumpFileMode  = 0o600
)

// requirePostgresDump: a PostgreSQL migration does not run without its dump.
var requirePostgresDump atomic.Bool

// RequirePostgresDump decides what a dump that cannot be taken costs. On, the
// migration does not run and the gateway does not start. Off, the gateway
// says so loudly and migrates.
//
// It is on only when the upgrade helper is waiting for this gateway: the
// helper then puts the previous release back, on a database nothing has
// touched. A gateway upgraded by a package, or a new container image, has
// nobody to put anything back, and refusing to start there would turn a
// missing client program into an outage.
func RequirePostgresDump(on bool) { requirePostgresDump.Store(on) }

// postgresSources remembers the URL each PostgreSQL pool was opened with:
// pg_dump connects for itself and needs to be told where. A gateway opens a
// handful of pools and keeps them for its lifetime.
var postgresSources struct {
	sync.Mutex
	urls map[*sql.DB]string
}

func rememberPostgresSource(db *sql.DB, url string) {
	postgresSources.Lock()
	defer postgresSources.Unlock()
	if postgresSources.urls == nil {
		postgresSources.urls = make(map[*sql.DB]string)
	}
	postgresSources.urls[db] = url
}

func postgresSource(db *sql.DB) string {
	postgresSources.Lock()
	defer postgresSources.Unlock()
	return postgresSources.urls[db]
}

// forgetPostgresSource drops what was remembered about a pool. Tests open
// many; a gateway keeps the few it opens.
func forgetPostgresSource(db *sql.DB) {
	postgresSources.Lock()
	defer postgresSources.Unlock()
	delete(postgresSources.urls, db)
}

// errNoDump wraps every reason a dump was not taken.
var errNoDump = errors.New("the PostgreSQL database was not dumped")

// postgresDumpPath names the dump of the database db is connected to, in
// the gateway's data directory.
func postgresDumpPath(db *sql.DB) (path, schema string, err error) {
	var database string
	if err := db.QueryRow("SELECT current_database(), current_schema()").Scan(&database, &schema); err != nil {
		return "", "", fmt.Errorf("%w: ask the server which database this is: %w", errNoDump, err)
	}
	return filepath.Join(config.DataDir(), "postgres-"+fileSafe(database)+PostgresDumpSuffix), schema, nil
}

// fileSafe keeps letters, digits, dot, dash and underscore of a database
// name, so the name cannot leave the data directory.
func fileSafe(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "database"
	}
	return b.String()
}

// dumpPostgres writes the schema the gateway uses, with its data, to path in
// pg_dump's custom format, which pg_restore reads. The previous dump is
// replaced only by a complete new one.
func dumpPostgres(db *sql.DB, path, schema string) error {
	source := postgresSource(db)
	if source == "" {
		return fmt.Errorf("%w: this connection was not opened from a database URL", errNoDump)
	}
	env, err := postgresEnv(source)
	if err != nil {
		return fmt.Errorf("%w: %w", errNoDump, err)
	}
	program, err := exec.LookPath(pgDump)
	if err != nil {
		return fmt.Errorf("%w: %s is not installed on this host: %w", errNoDump, pgDump, err)
	}
	partial := path + ".partial"
	// #nosec G304 -- in the gateway's data directory, named from the server's own answer through fileSafe.
	out, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, dumpFileMode)
	if err != nil {
		return fmt.Errorf("%w: %w", errNoDump, err)
	}
	err = runDump(program, env, schema, out)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(partial, path)
	}
	if err != nil {
		_ = os.Remove(partial)
		return fmt.Errorf("%w: %w", errNoDump, err)
	}
	return nil
}

// dumpArgs is what pg_dump is told. Where to connect and as whom is in its
// environment, never here: a command line is readable by every account.
func dumpArgs(schema string) []string {
	quoted := `"` + strings.ReplaceAll(schema, `"`, `""`) + `"`
	return []string{"--format=custom", "--no-owner", "--no-privileges", "--no-password", "--schema=" + quoted}
}

func runDump(program string, env []string, schema string, out *os.File) error {
	ctx, cancel := context.WithTimeout(context.Background(), postgresDumpTimeout)
	defer cancel()
	// #nosec G204 -- the program is pg_dump from PATH and the arguments are fixed but for the quoted schema name.
	cmd := exec.CommandContext(ctx, program, dumpArgs(schema)...)
	var complaint bytes.Buffer
	cmd.Env, cmd.Stdout, cmd.Stderr = env, out, &boundedWriter{buf: &complaint, limit: maxDumpStderr}
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%s did not finish in %s", pgDump, postgresDumpTimeout)
		}
		return fmt.Errorf("%s: %w: %s", pgDump, err, strings.TrimSpace(complaint.String()))
	}
	return out.Sync()
}

// boundedWriter keeps the first limit bytes and discards the rest.
type boundedWriter struct {
	buf   *bytes.Buffer
	limit int
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if room := w.limit - w.buf.Len(); room > 0 {
		w.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

// postgresParams are the connection settings of a database URL that libpq
// also reads from its environment.
var postgresParams = map[string]string{
	"sslmode":         "PGSSLMODE",
	"sslrootcert":     "PGSSLROOTCERT",
	"sslcert":         "PGSSLCERT",
	"sslkey":          "PGSSLKEY",
	"connect_timeout": "PGCONNECT_TIMEOUT",
	"options":         "PGOPTIONS",
}

// postgresEnv is the environment pg_dump runs in: the connection the URL
// names and the PATH, and nothing else the gateway happens to hold.
func postgresEnv(source string) ([]string, error) {
	u, err := neturl.Parse(source)
	if err != nil || u.Hostname() == "" {
		return nil, errors.New("the database URL names no host")
	}
	env := []string{"PATH=" + os.Getenv("PATH"), "PGHOST=" + u.Hostname(), "PGAPPNAME=gateon-pre-upgrade-dump"}
	add := func(name, value string) {
		if value != "" {
			env = append(env, name+"="+value)
		}
	}
	add("PGPORT", u.Port())
	add("PGDATABASE", strings.TrimPrefix(u.Path, "/"))
	if u.User != nil {
		add("PGUSER", u.User.Username())
		password, _ := u.User.Password()
		add("PGPASSWORD", password)
	}
	for param, name := range postgresParams {
		add(name, u.Query().Get(param))
	}
	return env, nil
}
