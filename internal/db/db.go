// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"strconv"
	"strings"
)

// Driver names for database/sql.
const (
	DriverSQLite   = "sqlite"
	DriverPostgres = "postgres"

	// DriverMySQL and DriverMariaDB are unreachable: Open refuses mysql:// and
	// mariadb://, so no Dialect is ever constructed with them. The constants and
	// the `case DriverMySQL` branches throughout this package are dead code kept
	// only so the diff that removed the support stayed readable.
	//
	// Do not maintain those branches, and do not take them as evidence the
	// engine works. They are written in a dialect MySQL does not accept: 43 of
	// 62 migrations fail on a real server, most on ADD COLUMN IF NOT EXISTS and
	// DEFAULT values on TEXT columns. Re-enabling the engine means rewriting
	// them against a MySQL in CI, not deleting the guard in Open.
	DriverMySQL   = "mysql"
	DriverMariaDB = "mysql" // MariaDB uses the MySQL driver
)

// Dialect describes database-specific behavior.
type Dialect struct {
	Driver string
}

// Rebind converts ? placeholders to the dialect's placeholder style.
// PostgreSQL uses $1, $2, ...; SQLite and MySQL use ?.
func (d Dialect) Rebind(query string) string {
	if d.Driver == DriverPostgres || d.Driver == "pgx" {
		n := 1
		var b strings.Builder
		for _, r := range query {
			if r == '?' {
				b.WriteString("$")
				b.WriteString(strconv.Itoa(n))
				n++
			} else {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	return query
}

// Params returns the rebinder function for prepared statements.
// Callers write queries with ? and pass through Rebind before Exec/Query.
func (d Dialect) Params(query string) string {
	return d.Rebind(query)
}
