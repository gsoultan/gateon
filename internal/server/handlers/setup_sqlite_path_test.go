// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// During first-run setup, POST /v1/setup/test-db and POST /v1/setup open a
// database the caller names, before anyone has authenticated. For SQLite the
// path went to restrictSQLiteFiles, which creates the file when it is missing
// and strips group and other permissions from one that exists -- so a caller
// could create an empty file anywhere the gateway can write, or chmod any
// file it owns: /etc/passwd, for a gateway running as root. A database named
// over the network now has to live in the data directory.
func TestSetupCannotPointSQLiteOutsideTheDataDirectory(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", dataDir)
	t.Chdir(dataDir) // as packaged: the unit and the image run from the data directory
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("not a database"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, dsn := range []string{victim, "sqlite://" + victim, "file:" + victim} {
		rr := postTestDB(t, &setupStateAPI{required: true}, `{"database_url":"`+dsn+`"}`)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("test-db with %q answered %d, want 400", dsn, rr.Code)
		}
		if err := validateDatabase(dsn, nil); err == nil {
			t.Errorf("setup accepted %q as its database", dsn)
		}
	}
	info, err := os.Stat(victim)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("a file outside the data directory was changed by setup: mode %v, err %v", info.Mode().Perm(), err)
	}

	// Control: the data directory is still where setup may put the database.
	inside := filepath.Join(dataDir, "gateon.db")
	if rr := postTestDB(t, &setupStateAPI{required: true}, `{"database_url":"`+inside+`"}`); rr.Code != http.StatusOK {
		t.Fatalf("test-db with a database in the data directory answered %d: %s", rr.Code, rr.Body.String())
	}
}

// The path was not the only part of the url that reached the file system.
// Every _pragma in a query string runs as SQL when the database opens, and a
// percent-encoded semicolon lets one carry an ATTACH, which creates a
// database wherever it names -- from a url whose path is in the data
// directory. And SQLite percent-decodes a file: URI after a check on the
// string has passed it, so "..%2F" climbs out of a directory the string never
// left. The wizard's own form reaches the same opener through sqlite_path.
func TestSetupCannotReachOutsideTheDataDirectoryThroughTheRestOfTheURL(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", dataDir)
	t.Chdir(dataDir)       // as packaged: the unit and the image run from the data directory
	outside := t.TempDir() // a sibling of dataDir
	inside := filepath.Join(dataDir, "gateon.db")
	attach := func(name string) string {
		return "?_pragma=" + url.QueryEscape("busy_timeout(5000);ATTACH DATABASE '"+
			filepath.Join(outside, name)+"' AS a;CREATE TABLE a.t(x);--")
	}
	escapes := map[string]string{
		"scheme.db": "sqlite://" + inside + attach("scheme.db"),
		"plain.db":  inside + attach("plain.db"),
		"climb.db":  "file:" + dataDir + "/..%2F" + filepath.Base(outside) + "%2Fclimb.db",
	}
	for name, dsn := range escapes {
		body, err := json.Marshal(map[string]string{"database_url": dsn})
		if err != nil {
			t.Fatal(err)
		}
		if rr := postTestDB(t, &setupStateAPI{required: true}, string(body)); rr.Code != http.StatusBadRequest {
			t.Errorf("test-db with %q answered %d, want 400", dsn, rr.Code)
		}
		if err := validateDatabase(dsn, nil); err == nil {
			t.Errorf("setup accepted %q as its database", dsn)
		}
		if _, err := os.Stat(filepath.Join(outside, name)); err == nil {
			t.Errorf("setup with %q created %s outside the data directory", dsn, name)
		}
	}

	form := &gateonv1.DatabaseConfig{Driver: "sqlite", SqlitePath: inside + attach("form.db")}
	if err := validateDatabase("", form); err == nil {
		t.Errorf("setup accepted sqlite_path %q", form.SqlitePath)
	}
	if _, err := os.Stat(filepath.Join(outside, "form.db")); err == nil {
		t.Error("setup's sqlite_path created form.db outside the data directory")
	}
}
