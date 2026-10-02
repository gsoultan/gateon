// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package auditrecord_test proves, against the real audit log, that a change
// to the audit settings is recorded before it takes effect (ADR 0040, M8).
//
// It is its own test binary because the audit log is process-global
// (audit.Init runs once): giving it a database here would change what every
// other test in internal/api writes, and this package owns the one it opens.
package auditrecord_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	dir, err := os.MkdirTemp("", "gateon-auditrecord-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := audit.Init(&gateonv1.AuditConfig{Enabled: true}, "sqlite:"+filepath.Join(dir, "audit.db")); err != nil {
		fmt.Fprintln(os.Stderr, "audit init:", err)
		return 1
	}
	defer audit.Stop()
	return m.Run()
}

// uniqueID tells this run's entries from those of an earlier -count run,
// which share the database.
func uniqueID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// serviceWithAuditOn stores a configuration with audit on, puts the audit log
// under it, and returns the service that saves the global configuration.
func serviceWithAuditOn(t *testing.T) (*api.ApiService, *gateonv1.GlobalConfig) {
	t.Helper()
	t.Setenv("GATEON_ENCRYPTION_KEY", "")
	reg := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	stored := &gateonv1.GlobalConfig{
		Auth:  &gateonv1.AuthConfig{Enabled: true, PasetoSecret: "0123456789abcdef0123456789abcdef"},
		Audit: &gateonv1.AuditConfig{Enabled: true, RetentionDays: 90},
	}
	if err := reg.Update(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	audit.UpdateConfig(stored.GetAudit())
	t.Cleanup(func() { audit.UpdateConfig(&gateonv1.AuditConfig{Enabled: true}) })
	clone, ok := proto.Clone(reg.Get(context.Background())).(*gateonv1.GlobalConfig)
	if !ok {
		t.Fatal("clone")
	}
	return &api.ApiService{Globals: reg}, clone
}

func entriesBy(t *testing.T, userID string) []audit.AuditEntry {
	t.Helper()
	logs, err := audit.GetLogs(context.Background(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.AuditEntry
	for _, e := range logs {
		if e.UserID == userID {
			out = append(out, e)
		}
	}
	return out
}

// TestSwitchingAuditOffIsItselfAudited is M8: an administrator (or, before
// ADR 0040, an operator) switching audit off left no entry, because the save
// was recorded after it -- by which time audit was off. The log held the
// enable and nothing after it. The change is now the last thing it records.
func TestSwitchingAuditOffIsItselfAudited(t *testing.T) {
	svc, conf := serviceWithAuditOn(t)
	id := "admin-" + uniqueID(t)
	ctx := context.WithValue(context.Background(), middleware.UserContextKey,
		&auth.Claims{ID: id, Username: "admin", Role: auth.RoleAdmin})

	conf.Audit.Enabled = false
	if _, err := svc.UpdateGlobalConfig(ctx, &gateonv1.UpdateGlobalConfigRequest{Config: conf}); err != nil {
		t.Fatalf("an administrator switching audit off: %v", err)
	}

	var recorded bool
	for _, e := range entriesBy(t, id) {
		if e.Resource == "audit_config" && strings.Contains(e.Details, "audit.enabled true -> false") {
			recorded = true
		}
	}
	if !recorded {
		t.Fatalf("switching audit off left no audit entry naming it; entries by the caller: %+v", entriesBy(t, id))
	}

	// And it did go off: what follows is not recorded.
	audit.Log(ctx, id, "after", "probe", "written after audit was switched off", "")
	for _, e := range entriesBy(t, id) {
		if e.Action == "after" {
			t.Fatal("audit was still on after the save switched it off")
		}
	}
}

// TestOperatorCannotSwitchAuditOff: the audit section is administrator-only,
// so the silent switch-off M8 describes is refused outright for an operator.
func TestOperatorCannotSwitchAuditOff(t *testing.T) {
	svc, conf := serviceWithAuditOn(t)
	ctx := context.WithValue(context.Background(), middleware.UserContextKey,
		&auth.Claims{ID: "op-" + uniqueID(t), Username: "operator", Role: auth.RoleOperator})

	conf.Audit.Enabled = false
	_, err := svc.UpdateGlobalConfig(ctx, &gateonv1.UpdateGlobalConfigRequest{Config: conf})
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "audit.enabled") {
		t.Fatalf("an operator switching audit off got %v, want PermissionDenied naming audit.enabled", err)
	}
	if !svc.Globals.Get(ctx).GetAudit().GetEnabled() {
		t.Fatal("the refused save switched audit off anyway")
	}
}
