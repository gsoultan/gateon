// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import "testing"

// TestDescribeNamesTheDatabaseWithoutItsCredentials: the setup wizard shows
// this to the operator (ADR 0057), so the password and user must not be in it.
func TestDescribeNamesTheDatabaseWithoutItsCredentials(t *testing.T) {
	for _, c := range []struct {
		url, driver, where string
	}{
		{"postgres://gateon:s3cret@db.internal:5432/gateon?sslmode=require", DriverPostgres, "db.internal:5432/gateon"},
		{"postgresql://db.internal/gateon", DriverPostgres, "db.internal/gateon"},
		{"host=db user=gateon password=s3cret", DriverSQLite, ""},
		{"/var/lib/gateon/gateon.db", DriverSQLite, "/var/lib/gateon/gateon.db"},
		{"sqlite:gateon.db", DriverSQLite, "gateon.db"},
		{"mysql://u:p@tcp(db:3306)/gateon", "", ""},
	} {
		driver, where := Describe(c.url)
		if driver != c.driver || where != c.where {
			t.Errorf("Describe(%q) = (%q, %q), want (%q, %q)", c.url, driver, where, c.driver, c.where)
		}
	}
}

// TestSameDatabaseReadsSpellingsOfOneSQLiteFile: the wizard's spelling of the
// database global.json names must not read as a different one.
func TestSameDatabaseReadsSpellingsOfOneSQLiteFile(t *testing.T) {
	same := [][2]string{
		{"/d/gateon.db", "sqlite:/d/gateon.db"},
		{"sqlite:///d/gateon.db", "/d/./gateon.db"},
		{"postgres://h/db", " postgres://h/db"},
	}
	for _, p := range same {
		if !SameDatabase(p[0], p[1]) {
			t.Errorf("SameDatabase(%q, %q) = false, want true", p[0], p[1])
		}
	}
	different := [][2]string{
		{"/d/gateon.db", "/d/other.db"},
		{"/d/gateon.db", "postgres://h/gateon.db"},
		{"postgres://h/a", "postgres://h/b"},
	}
	for _, p := range different {
		if SameDatabase(p[0], p[1]) {
			t.Errorf("SameDatabase(%q, %q) = true, want false", p[0], p[1])
		}
	}
}
