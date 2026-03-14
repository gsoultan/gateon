package db

import (
	"strconv"
	"strings"
)

// Driver names for database/sql.
const (
	DriverSQLite    = "sqlite"
	DriverPostgres  = "postgres"
	DriverMySQL     = "mysql"
	DriverMariaDB   = "mysql" // MariaDB uses the MySQL driver
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
