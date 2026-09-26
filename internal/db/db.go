// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// Driver names for database/sql.
const (
	DriverSQLite   = "sqlite"
	DriverPostgres = "postgres"
)

// Dialect describes database-specific behavior.
type Dialect struct {
	Driver string
}

// Rebind converts ? placeholders to the dialect's placeholder style.
// PostgreSQL uses $1, $2, ...; SQLite uses ?.
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

// SafeText returns s in a form every supported engine will store.
//
// Postgres refuses a TEXT or VARCHAR value that is not valid UTF-8 or that
// contains a NUL byte, and refuses the whole statement for it -- inside a
// transaction, the whole transaction. SQLite stores either without complaint.
// A lot of what gateon persists is copied from requests, and Go's HTTP server
// hands a handler both: a percent-encoded %00 or %FF decodes into r.URL.Path,
// and a header value may carry any byte above 0x7F. So on Postgres a client
// could decide which of its own requests were not recorded. Invalid sequences
// and NUL become U+FFFD, which is what encoding/json turns them into on the way
// to the dashboard anyway. Text that is already storable is returned as is,
// without allocating.
func SafeText(s string) string {
	if utf8.ValidString(s) && strings.IndexByte(s, 0) < 0 {
		return s
	}
	return strings.ReplaceAll(strings.ToValidUTF8(s, "�"), "\x00", "�")
}
