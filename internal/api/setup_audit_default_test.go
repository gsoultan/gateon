// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func newSetupService(t *testing.T) (*ApiService, string) {
	t.Helper()
	t.Setenv("GATEON_ENCRYPTION_KEY", "")
	tmp := t.TempDir()
	mgr, err := auth.NewManager(filepath.Join(tmp, "auth.db"), strings.Repeat("k", 32), logger.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	path := filepath.Join(tmp, "global.json")
	return &ApiService{
		Auth:       auth.NewHolder(mgr),
		Globals:    config.NewGlobalRegistry(path),
		SetupToken: newTestSetupToken(t),
	}, path
}

// TestSetupTurnsTheAuditLogOnSigned is M8 for new installs: audit was off by
// default, so a default install recorded nothing -- the review's showed
// totalCount 0 after setup, user creation, global writes and failed sign-ins
// -- and with signing off there was no chain to verify either.
func TestSetupTurnsTheAuditLogOnSigned(t *testing.T) {
	svc, path := newSetupService(t)
	resp, err := svc.Setup(context.Background(), &gateonv1.SetupRequest{
		AdminUsername: "admin", AdminPassword: "first-run-passphrase", PasetoSecret: strings.Repeat("a", 32),
		SetupToken: svc.SetupToken.Value(),
	})
	if err != nil || !resp.Success {
		t.Fatalf("Setup: err=%v resp=%+v", err, resp)
	}
	a := svc.Globals.Get(context.Background()).GetAudit()
	if !a.GetEnabled() || !a.GetSignEntries() || len(a.GetSignatureKey()) < 32 {
		t.Fatalf("after setup the audit log is enabled=%v signed=%v key=%d bytes; want on, signed, with a key",
			a.GetEnabled(), a.GetSignEntries(), len(a.GetSignatureKey()))
	}
	// And so after a restart: it is the stored configuration, not only the live one.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Audit struct {
			Enabled     bool `json:"enabled"`
			SignEntries bool `json:"sign_entries"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if !stored.Audit.Enabled || !stored.Audit.SignEntries {
		t.Errorf("global.json holds audit %+v; want it on and signed", stored.Audit)
	}
}

// TestSetupRefusesAWeakAdministratorPassword before it writes anything (M11).
func TestSetupRefusesAWeakAdministratorPassword(t *testing.T) {
	svc, path := newSetupService(t)
	resp, err := svc.Setup(context.Background(), &gateonv1.SetupRequest{
		AdminUsername: "admin", AdminPassword: "a", PasetoSecret: strings.Repeat("a", 32),
		SetupToken: svc.SetupToken.Value(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Success || !strings.Contains(resp.Error, "at least 12 characters") {
		t.Fatalf("Setup with password %q: %+v, want refused naming the rule", "a", resp)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("a refused setup wrote the configuration: %v", err)
	}
	if required, _ := svc.IsSetupRequired(context.Background(), &gateonv1.IsSetupRequiredRequest{}); !required.GetRequired() {
		t.Error("a refused setup left setup no longer required")
	}
}
