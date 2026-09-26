// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// TestSetupTestDBRequiresTheSetupToken: until setup completes, the connection
// test is a database connection a caller who has not signed in can make the
// gateway open, to an address of their choosing. It asked for nothing. Without
// the setup token it now opens nothing.
func TestSetupTestDBRequiresTheSetupToken(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", dataDir)
	t.Chdir(dataDir)
	probed := filepath.Join(dataDir, "probed.db")
	body := func(token string) string {
		return `{"databaseUrl":"` + probed + `","setupToken":"` + token + `"}`
	}

	for name, token := range map[string]string{"no token": "", "wrong token": "not-the-setup-token"} {
		t.Run(name, func(t *testing.T) {
			rr := postTestDBWith(t, &setupStateAPI{required: true}, &Deps{SetupToken: testSetupToken}, body(token))
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 without the setup token: %s", rr.Code, rr.Body)
			}
			// Opening a SQLite database creates its file.
			if _, err := os.Stat(probed); !os.IsNotExist(err) {
				t.Fatalf("the connection test opened a database without the token (stat err = %v)", err)
			}
		})
	}
	// A gateway wired without a token keeps the test closed rather than open.
	if rr := postTestDBWith(t, &setupStateAPI{required: true}, &Deps{}, body("")); rr.Code != http.StatusForbidden {
		t.Errorf("with no setup token wired in, status = %d, want 403", rr.Code)
	}

	// Control: the same request with the token opens the database.
	rr := postTestDBWith(t, &setupStateAPI{required: true}, &Deps{SetupToken: testSetupToken}, body(testSetupToken.Value()))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d with the setup token, want 200: %s", rr.Code, rr.Body)
	}
	if _, err := os.Stat(probed); err != nil {
		t.Errorf("the connection test did not open the database it was given: %v", err)
	}
}
