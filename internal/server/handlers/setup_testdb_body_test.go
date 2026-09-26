// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// TestSetupTestDBReadsTheBodyTheWizardSends is the "Test connection" button
// as the dashboard presses it.
//
// The handler decoded with encoding/json into snake_case tags, and the wizard
// sends protojson's lowerCamel. No key matched -- not even case-insensitively,
// because an underscore is not a capital letter -- so the body decoded empty
// and every press answered 400 "missing database configuration", whatever the
// operator had filled in. The form had the same fault one level down:
// "sqlitePath" never reached the generated `json:"sqlite_path"` tag.
func TestSetupTestDBReadsTheBodyTheWizardSends(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", dataDir)
	t.Chdir(dataDir) // a fallback to the default gateon.db lands here, not in the checkout

	for name, tc := range map[string]struct{ body, file string }{
		"connection string": {
			body: `{"databaseUrl":"` + filepath.Join(dataDir, "by-url.db") + `"}`,
			file: "by-url.db",
		},
		"form": {
			body: `{"databaseConfig":{"driver":"sqlite","sqlitePath":"` + filepath.Join(dataDir, "by-form.db") + `"}}`,
			file: "by-form.db",
		},
	} {
		t.Run(name, func(t *testing.T) {
			rr := postTestDB(t, &setupStateAPI{required: true}, tc.body)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 for the body the wizard sends: %s", rr.Code, rr.Body)
			}
			// The database named, not merely one that opens: a form whose
			// sqlitePath is dropped still succeeds, because BuildURLFromConfig
			// falls back to gateon.db -- and tests a database nobody chose.
			if _, err := os.Stat(filepath.Join(dataDir, tc.file)); err != nil {
				t.Errorf("test-db did not open the database it was given: %v", err)
			}
		})
	}
}
