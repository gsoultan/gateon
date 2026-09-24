// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"errors"
	neturl "net/url"
	"strings"
	"testing"
)

// MySQL and MariaDB were accepted by Open and served by nothing. Refusing the
// URL is the whole fix, so it is the thing to test: accepting it and failing at
// migration 2 is a startup failure after the operator has committed to the
// engine, which is exactly the outcome being removed.
func TestOpenRefusesEnginesThatNeverWorked(t *testing.T) {
	for _, url := range []string{
		"mysql://user:hunter2@tcp(db:3306)/gateon",
		"mariadb://user:hunter2@tcp(db:3306)/gateon",
		"MySQL://user:hunter2@tcp(db:3306)/gateon",
	} {
		t.Run(url[:strings.Index(url, ":")], func(t *testing.T) {
			conn, _, err := Open(url)
			if conn != nil {
				_ = conn.Close()
				t.Fatal("Open returned a usable connection for an unsupported engine")
			}
			if !errors.Is(err, ErrUnsupportedEngine) {
				t.Fatalf("got %v, want ErrUnsupportedEngine", err)
			}
			// The DSN carries a password. An error that quotes the URL back ends
			// up in logs, issue reports and support threads.
			if strings.Contains(err.Error(), "hunter2") {
				t.Errorf("error leaks the DSN password: %v", err)
			}
			// It must name the supported engines, or the reader has to go
			// looking for what to use instead.
			for _, want := range []string{"sqlite", "postgres"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not mention %q: %v", want, err)
				}
			}
		})
	}
}

// The engines that do work must be unaffected, including the bare-path form.
func TestOpenStillParsesSupportedEngines(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{url: "sqlite:gateon.db", want: DriverSQLite},
		{url: "sqlite://gateon.db", want: DriverSQLite},
		{url: "gateon.db", want: DriverSQLite},
		{url: "postgres://u:p@h:5432/d?sslmode=disable", want: DriverPostgres},
		{url: "postgresql://u:p@h:5432/d?sslmode=disable", want: DriverPostgres},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			if _, name := refusedEngine(tc.url); name != "" {
				t.Fatalf("%q was refused as %s", tc.url, name)
			}
			if got, _ := parseURL(tc.url); got != tc.want {
				t.Errorf("parseURL(%q) = %q, want %q", tc.url, got, tc.want)
			}
		})
	}
}

// A Postgres session always runs in UTC, whatever zone the DSN or the server
// asked for, and the rest of the DSN survives the rewrite. What this protects
// is tested end to end by TestFingerprintMitigationTTLIgnoresTheDatabaseZone in
// internal/telemetry; this pins the rewrite itself, including the spellings
// that would otherwise reach the server as a second, competing parameter.
func TestPostgresSessionZoneIsPinnedToUTC(t *testing.T) {
	for _, dsn := range []string{
		"postgres://u:p%40ss@h:5432/d?sslmode=disable",
		"postgres://u:p%40ss@h:5432/d?sslmode=disable&timezone=Asia/Jakarta",
		"postgresql://u:p%40ss@h:5432/d?TimeZone=America%2FNew_York&sslmode=disable",
	} {
		_, got := parseURL(dsn)
		u, err := neturl.Parse(got)
		if err != nil {
			t.Fatalf("rewritten DSN does not parse: %v", err)
		}
		q := u.Query()
		if len(q) != 2 || q.Get("timezone") != "UTC" || q.Get("sslmode") != "disable" {
			t.Errorf("%s: parameters after the rewrite are %v, want sslmode=disable and timezone=UTC only",
				u.Redacted(), q)
		}
		if pw, _ := u.User.Password(); pw != "p@ss" || u.Host != "h:5432" || u.Path != "/d" {
			t.Errorf("the rewrite changed the connection target: %s", u.Redacted())
		}
	}
}
