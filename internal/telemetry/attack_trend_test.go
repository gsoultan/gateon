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
		{"SQLiteHourly", db.DriverSQLite, false, "%Y-%m-%d %H:00:00"},
		{"SQLiteDaily", db.DriverSQLite, true, "%Y-%m-%d 00:00:00"},
		{"PostgresHourly", db.DriverPostgres, false, "YYYY-MM-DD HH24:00:00"},
		{"PostgresDaily", db.DriverPostgres, true, "YYYY-MM-DD 00:00:00"},
		{"PgxDaily", "pgx", true, "YYYY-MM-DD 00:00:00"},
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
