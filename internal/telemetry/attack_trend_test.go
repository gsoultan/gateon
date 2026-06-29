package telemetry

import (
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
)

func TestAttackTrendBucketQuery(t *testing.T) {
	tests := []struct {
		name       string
		driver     string
		daily      bool
		wantSubstr string
	}{
		{"SQLiteHourly", db.DriverSQLite, false, "strftime('%Y-%m-%d %H:00:00', timestamp)"},
		{"SQLiteDaily", db.DriverSQLite, true, "date(timestamp)"},
		{"PostgresHourly", db.DriverPostgres, false, "date_trunc('hour', timestamp)"},
		{"PostgresDaily", db.DriverPostgres, true, "date_trunc('day', timestamp)"},
		{"PgxDaily", "pgx", true, "date_trunc('day', timestamp)"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := attackTrendBucketQuery(tc.driver, tc.daily)
			if !strings.Contains(got, tc.wantSubstr) {
				t.Errorf("%s: query %q does not contain %q", tc.name, got, tc.wantSubstr)
			}
			if !strings.Contains(got, "timestamp >= ?") {
				t.Errorf("%s: query %q must filter on timestamp >= ?", tc.name, got)
			}
		})
	}
}
