package db

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestAuditDatabaseURL(t *testing.T) {
	authSqlite := &gateonv1.AuthConfig{SqlitePath: "auth.db"}

	tests := []struct {
		name  string
		audit *gateonv1.AuditConfig
		auth  *gateonv1.AuthConfig
		want  string
	}{
		{
			name:  "nil audit falls back to auth",
			audit: nil,
			auth:  authSqlite,
			want:  "auth.db",
		},
		{
			name:  "empty audit falls back to auth",
			audit: &gateonv1.AuditConfig{},
			auth:  authSqlite,
			want:  "auth.db",
		},
		{
			name:  "audit database_url takes precedence",
			audit: &gateonv1.AuditConfig{DatabaseUrl: "logs.db"},
			auth:  authSqlite,
			want:  "logs.db",
		},
		{
			name: "audit database_config preferred over url",
			audit: &gateonv1.AuditConfig{
				DatabaseUrl:    "logs.db",
				DatabaseConfig: &gateonv1.DatabaseConfig{Driver: "sqlite", SqlitePath: "config-logs.db"},
			},
			auth: authSqlite,
			want: "config-logs.db",
		},
		{
			name:  "nil audit and nil auth defaults to gateon.db",
			audit: nil,
			auth:  nil,
			want:  "gateon.db",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := AuditDatabaseURL(tc.audit, tc.auth)
			if got != tc.want {
				t.Errorf("AuditDatabaseURL() = %q; want %q", got, tc.want)
			}
		})
	}
}
