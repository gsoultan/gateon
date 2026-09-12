// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"errors"
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
