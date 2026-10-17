// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestRouteWAFAuditLogPathIsRefusedAtSave (ADR 0079): the save path every
// transport reaches through the domain service refuses a route WAF whose
// audit_log_path leaves <data-dir>/audit/waf/, before Create would make the
// directory and open the file -- and saves a name inside it.
func TestRouteWAFAuditLogPathIsRefusedAtSave(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", dir)
	f := NewFactory(nil, nil, nil, nil, dir)
	validate := func(p string) error {
		return f.Validate(&gateonv1.Middleware{Id: "w", Type: "waf", Config: map[string]string{"audit_log_path": p}})
	}
	victim := filepath.Join(dir, "global.yaml")
	for _, p := range []string{"/var/lib/gateon/global.yaml", victim, "../../x"} {
		if err := validate(p); err == nil || !strings.Contains(err.Error(), "audit/waf") {
			t.Errorf("audit_log_path %q: err = %v, want the save refused naming the audit directory", p, err)
		}
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Errorf("a refused save created %s: %v", victim, err)
	}
	if err := validate("myroute.log"); err != nil {
		t.Errorf("a name inside the audit directory was refused: %v", err)
	}
}
