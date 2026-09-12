// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// schemaProbe reads and populates a schema without knowing what is in it.
//
// The upgrade tests need to insert a representative row into every table a past
// release shipped, and the whole point of those tests is that the table list
// changes as migrations are added. A hardcoded set of INSERT statements would
// therefore describe the schema as it was on the day it was written and quietly
// stop covering anything added since. Reading the columns back from the
// database instead keeps the fixture honest for free.
type schemaProbe struct {
	t       *testing.T
	db      *sql.DB
	dialect Dialect
}

// probeColumn is the subset of a column definition the seeder needs: enough to
// produce a value the database will accept.
type probeColumn struct {
	name string
	typ  string
	pk   bool
	// maxLen is the declared character limit, 0 when unbounded. Ignoring it is
	// how a seeder ends up reporting "value too long for type character
	// varying(5)" and skipping the row it was supposed to be testing with.
	maxLen int
}

// reDeclaredLen pulls the length out of a SQLite type such as VARCHAR(255);
// the other dialects report it as a separate information_schema column.
var reDeclaredLen = regexp.MustCompile(`\((\d+)\)`)

// tables lists the user tables, excluding the migration ledger itself.
func (p schemaProbe) tables() []string {
	var q string
	switch p.dialect.Driver {
	case DriverSQLite:
		q = `SELECT name FROM sqlite_master WHERE type='table'
		       AND name NOT LIKE 'sqlite_%' AND name <> 'migrations' ORDER BY name`
	case DriverPostgres:
		q = `SELECT table_name FROM information_schema.tables
		       WHERE table_schema='public' AND table_type='BASE TABLE'
		       AND table_name <> 'migrations' ORDER BY table_name`
	default:
		q = `SELECT table_name FROM information_schema.tables
		       WHERE table_schema=DATABASE() AND table_type='BASE TABLE'
		       AND table_name <> 'migrations' ORDER BY table_name`
	}
	rows, err := p.db.Query(q)
	if err != nil {
		p.t.Fatalf("list tables: %v", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			p.t.Fatalf("scan table name: %v", err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		p.t.Fatalf("iterate tables: %v", err)
	}
	return out
}

// columns describes one table, in declaration order.
func (p schemaProbe) columns(table string) []probeColumn {
	if p.dialect.Driver == DriverSQLite {
		return p.sqliteColumns(table)
	}
	return p.infoSchemaColumns(table)
}

func (p schemaProbe) sqliteColumns(table string) []probeColumn {
	// PRAGMA takes no bind parameters, and table names here come from
	// sqlite_master, never from input.
	rows, err := p.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table)) //nolint:gosec
	if err != nil {
		p.t.Fatalf("pragma table_info(%s): %v", table, err)
	}
	defer rows.Close()

	var out []probeColumn
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			p.t.Fatalf("scan table_info(%s): %v", table, err)
		}
		length := 0
		if m := reDeclaredLen.FindStringSubmatch(typ); m != nil {
			length, _ = strconv.Atoi(m[1])
		}
		out = append(out, probeColumn{
			name: name, typ: strings.ToUpper(typ), pk: pk == 1, maxLen: length,
		})
	}
	if err := rows.Err(); err != nil {
		p.t.Fatalf("iterate table_info(%s): %v", table, err)
	}
	return out
}

func (p schemaProbe) infoSchemaColumns(table string) []probeColumn {
	q := `SELECT column_name, data_type, COALESCE(character_maximum_length, 0)
	        FROM information_schema.columns
	        WHERE table_schema = DATABASE() AND table_name = ?
	        ORDER BY ordinal_position`
	if p.dialect.Driver == DriverPostgres {
		q = `SELECT column_name, data_type, COALESCE(character_maximum_length, 0)
		       FROM information_schema.columns
		       WHERE table_schema = 'public' AND table_name = ?
		       ORDER BY ordinal_position`
	}
	rows, err := p.db.Query(p.dialect.Rebind(q), table)
	if err != nil {
		p.t.Fatalf("describe %s: %v", table, err)
	}
	defer rows.Close()

	var out []probeColumn
	for rows.Next() {
		var name, typ string
		var length int
		if err := rows.Scan(&name, &typ, &length); err != nil {
			p.t.Fatalf("scan description of %s: %v", table, err)
		}
		out = append(out, probeColumn{
			name: name, typ: strings.ToUpper(typ),
			pk: strings.EqualFold(name, "id"), maxLen: length,
		})
	}
	if err := rows.Err(); err != nil {
		p.t.Fatalf("iterate description of %s: %v", table, err)
	}
	return out
}

// seedValue produces a value the column will accept. Name is consulted before
// type because several columns are declared as free text but are read back by
// migrations that expect a particular shape -- a rule id inside a directive, a
// country code, a date key.
func seedValue(c probeColumn, row int) any {
	switch {
	case strings.Contains(c.typ, "BOOL"), c.typ == "TINYINT":
		return row%2 == 0
	case strings.Contains(c.typ, "TIMESTAMP"), strings.Contains(c.typ, "DATETIME"), c.typ == "DATE":
		return time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(row) * time.Hour)
	case strings.Contains(c.typ, "INT"), strings.Contains(c.typ, "NUMERIC"), strings.Contains(c.typ, "DECIMAL"):
		return row + 1
	case strings.Contains(c.typ, "REAL"), strings.Contains(c.typ, "DOUBLE"), strings.Contains(c.typ, "FLOAT"):
		return float64(row) + 0.5
	}
	return seedText(c, row)
}

func seedText(c probeColumn, row int) string {
	name := strings.ToLower(c.name)
	var v string
	switch {
	case name == "id" && c.pk:
		v = fmt.Sprintf("id-%d", row)
	case strings.Contains(name, "directive"):
		// Migration 51 rewrites rule ids inside the directive text.
		v = fmt.Sprintf(`SecRule ARGS "@rx attack" "id:9420%02d,phase:2,deny"`, row)
	case strings.Contains(name, "ja3"), strings.Contains(name, "ja4"):
		v = fmt.Sprintf("t13d1516h2_8daaf6152771_b0da82dd1%03d", row)
	case strings.Contains(name, "ip"):
		v = fmt.Sprintf("203.0.113.%d", row%250+1)
	case name == "day":
		v = "2026-01-01"
	case strings.Contains(name, "role"):
		v = "admin"
	case strings.Contains(name, "host"), strings.Contains(name, "domain"):
		v = fmt.Sprintf("app%d.example.com", row)
	case strings.Contains(name, "path"):
		v = fmt.Sprintf("/api/v%d/resource", row)
	default:
		v = fmt.Sprintf("%s-%d", name, row)
	}
	if c.maxLen > 0 && len(v) > c.maxLen {
		v = v[:c.maxLen]
	}
	return v
}

// seed inserts rowsPerTable rows into every table and reports what landed.
// A row the schema refuses is fatal: silently seeding nothing would turn a
// data-loss test into an empty-database test, which passes for free.
func (p schemaProbe) seed(rowsPerTable int) map[string]int {
	counts := make(map[string]int)
	for _, table := range p.tables() {
		cols := p.columns(table)
		if len(cols) == 0 {
			continue
		}
		names := make([]string, 0, len(cols))
		holders := make([]string, 0, len(cols))
		for _, c := range cols {
			names = append(names, c.name)
			holders = append(holders, "?")
		}
		stmt := p.dialect.Rebind(fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
			table, strings.Join(names, ", "), strings.Join(holders, ", ")))

		for row := 0; row < rowsPerTable; row++ {
			values := make([]any, 0, len(cols))
			for _, c := range cols {
				values = append(values, seedValue(c, row))
			}
			if _, err := p.db.Exec(stmt, values...); err != nil {
				p.t.Fatalf("seed %s row %d: %v", table, row, err)
			}
			counts[table]++
		}
	}
	return counts
}

// rowCounts reads the current size of each named table.
func (p schemaProbe) rowCounts(tables []string) map[string]int {
	out := make(map[string]int, len(tables))
	for _, table := range tables {
		var n int
		// Table names come from the catalogue, never from input.
		if err := p.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil { //nolint:gosec
			p.t.Errorf("table %q is unreadable after upgrade: %v", table, err)
			continue
		}
		out[table] = n
	}
	return out
}

// columnNames fingerprints the schema as table -> sorted column names. Types are
// deliberately excluded: they are spelled differently by each dialect, and the
// property worth asserting across an upgrade is that nothing is missing.
func (p schemaProbe) columnNames() map[string][]string {
	out := make(map[string][]string)
	for _, table := range p.tables() {
		var names []string
		for _, c := range p.columns(table) {
			names = append(names, strings.ToLower(c.name))
		}
		sort.Strings(names)
		out[table] = names
	}
	return out
}

// reset returns the database to empty, including the migration ledger, so the
// next Migrate runs the whole chain rather than resuming a half-built schema.
func (p schemaProbe) reset() {
	switch p.dialect.Driver {
	case DriverSQLite:
		p.dropAllTables()
	case DriverPostgres:
		if _, err := p.db.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
			p.t.Fatalf("reset postgres schema: %v", err)
		}
	case DriverMySQL:
		p.resetMySQL()
	}
}

// dropAllTables clears a SQLite database in place. Dropping is preferred over
// deleting the file because the probe holds an open handle to it.
func (p schemaProbe) dropAllTables() {
	for _, table := range append(p.tables(), "migrations") {
		if _, err := p.db.Exec("DROP TABLE IF EXISTS " + table); err != nil { //nolint:gosec
			p.t.Fatalf("drop %s: %v", table, err)
		}
	}
}

func (p schemaProbe) resetMySQL() {
	if _, err := p.db.Exec(`SET FOREIGN_KEY_CHECKS=0`); err != nil {
		p.t.Fatalf("disable foreign key checks: %v", err)
	}
	for _, table := range append(p.tables(), "migrations") {
		if _, err := p.db.Exec("DROP TABLE IF EXISTS " + table); err != nil { //nolint:gosec
			p.t.Fatalf("drop %s: %v", table, err)
		}
	}
	if _, err := p.db.Exec(`SET FOREIGN_KEY_CHECKS=1`); err != nil {
		p.t.Fatalf("re-enable foreign key checks: %v", err)
	}
}
