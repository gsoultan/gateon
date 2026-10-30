// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package dbtest

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
)

// PostgresDSNEnv names the server the Postgres tests run against. Unset, they
// skip.
const PostgresDSNEnv = "GATEON_TEST_POSTGRES_DSN"

// errNoRun is why Postgres refuses to build a template outside Run: the
// template is a database on a shared server, and only Run drops it.
var errNoRun = errors.New("dbtest.Postgres needs TestMain to call dbtest.Run, which drops the template it builds")

var postgresTemplate struct {
	running atomic.Bool
	once    sync.Once
	// clones serializes CREATE DATABASE ... TEMPLATE: Postgres refuses to copy
	// a template another session is connected to, and a concurrent copy is one.
	clones sync.Mutex
	admin  *sql.DB
	base   *url.URL
	name   string
	err    error
	// unavailable is set when the server would not give us a database at
	// all, which skips; a template that fails to migrate is a failure.
	unavailable bool
}

// Run runs the tests and then drops the Postgres template, if any test built
// one. A package that calls Postgres must call it from TestMain:
//
//	func TestMain(m *testing.M) { os.Exit(dbtest.Run(m)) }
func Run(m *testing.M) int {
	postgresTemplate.running.Store(true)
	code := m.Run()
	dropPostgresTemplate()
	return code
}

// Postgres returns the URL of a new database, on the server PostgresDSNEnv
// names, with every migration already applied. It is dropped when tb ends. The
// test skips when PostgresDSNEnv is unset or the server will not let it create
// a database.
func Postgres(tb testing.TB) string {
	tb.Helper()
	dsn := os.Getenv(PostgresDSNEnv)
	if dsn == "" {
		tb.Skipf("%s not set", PostgresDSNEnv)
	}
	if !postgresTemplate.running.Load() {
		tb.Fatal(errNoRun)
	}
	t := &postgresTemplate
	t.once.Do(func() { t.err = buildPostgresTemplate(dsn) })
	if t.err != nil && t.unavailable {
		tb.Skipf("cannot create a Postgres database: %v", t.err)
	}
	if t.err != nil {
		tb.Fatalf("build the migrated Postgres template: %v", t.err)
	}
	name := "gateon_test_" + randomSuffix()
	t.clones.Lock()
	_, err := t.admin.Exec("CREATE DATABASE " + name + " TEMPLATE " + t.name)
	t.clones.Unlock()
	if err != nil {
		tb.Fatalf("clone the migrated Postgres template: %v", err)
	}
	tb.Cleanup(func() {
		if _, err := t.admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)"); err != nil {
			tb.Logf("drop %s: %v", name, err)
		}
	})
	return databaseURL(t.base, name)
}

func buildPostgresTemplate(dsn string) error {
	t := &postgresTemplate
	base, err := url.Parse(dsn)
	if err == nil && base.Scheme == "" {
		err = errors.New("it has no scheme")
	}
	if err != nil {
		t.unavailable = true
		return fmt.Errorf("%s is not a URL a database can be derived from: %w", PostgresDSNEnv, err)
	}
	admin, _, err := db.Open(dsn)
	if err != nil {
		t.unavailable = true
		return fmt.Errorf("open %s: %w", base.Redacted(), err)
	}
	name := "gateon_template_" + randomSuffix()
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		_ = admin.Close()
		t.unavailable = true
		return fmt.Errorf("create %s: %w", name, err)
	}
	// From here the template exists, so Run must drop it whatever happens.
	t.admin, t.base, t.name = admin, base, name
	return migratePostgres(databaseURL(base, name))
}

// migratePostgres migrates the template and closes every connection to it,
// since Postgres will not copy a database anyone is connected to.
func migratePostgres(dsn string) error {
	database, dialect, err := db.Open(dsn)
	if err != nil {
		return fmt.Errorf("open the template: %w", err)
	}
	if err := db.Migrate(database, dialect); err != nil {
		_ = database.Close()
		return fmt.Errorf("migrate the template: %w", err)
	}
	return database.Close()
}

func dropPostgresTemplate() {
	t := &postgresTemplate
	if t.admin == nil {
		return
	}
	if _, err := t.admin.Exec("DROP DATABASE IF EXISTS " + t.name + " WITH (FORCE)"); err != nil {
		fmt.Fprintf(os.Stderr, "dbtest: drop %s: %v\n", t.name, err)
	}
	_ = t.admin.Close()
}

func databaseURL(base *url.URL, name string) string {
	u := *base
	u.Path = "/" + name
	return u.String()
}

// randomSuffix keeps names unique across test binaries sharing one server, and
// is hex so it can be spliced into a statement that takes no parameters.
func randomSuffix() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
