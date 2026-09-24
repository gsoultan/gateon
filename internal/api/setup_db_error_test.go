// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// lockedAtSetupCheck is the real Manager, except that the one read
// IsSetupRequired makes runs while another connection holds the database
// locked -- what a busy SQLite file, a restarting Postgres or an exhausted
// connection pool look like from the gateway. Every other call reaches the
// database normally, which is the transient shape those failures have.
type lockedAtSetupCheck struct {
	*auth.Manager
	t    *testing.T
	path string
}

func (s lockedAtSetupCheck) IsSetupDone() bool {
	s.t.Helper()
	locker, err := sql.Open("sqlite", s.path+"?_pragma=busy_timeout(0)")
	if err != nil {
		s.t.Fatalf("open locker: %v", err)
	}
	defer func() { _ = locker.Close() }()
	conn, err := locker.Conn(context.Background())
	if err != nil {
		s.t.Fatalf("locker conn: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(context.Background(), "BEGIN EXCLUSIVE"); err != nil {
		s.t.Fatalf("take the lock: %v", err)
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), "ROLLBACK") }()
	return s.Manager.IsSetupDone()
}

// TestSetupStaysClosedWhenTheUserTableCannotBeRead.
//
// Setup is public and served before authentication; the only thing keeping it
// from running again on a configured gateway is IsSetupRequired, which asks
// the auth store whether an administrator exists. The store answered with
// rows.Next(), which is false for an empty table and equally false for a query
// that failed -- so for as long as the database could not be read, a gateway
// with an administrator reported "setup required", and the next Setup call
// reused that administrator's id, replaced their password and installed the
// caller's PASETO secret.
func TestSetupStaysClosedWhenTheUserTableCannotBeRead(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "auth.db")
	// busy_timeout(0) so a locked read fails now rather than after the
	// production default of five seconds; the failure is the same one.
	mgr, err := auth.NewManager("sqlite:"+dbPath+"?_pragma=busy_timeout(0)", strings.Repeat("k", 32), logger.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	globals := config.NewGlobalRegistry(filepath.Join(tmp, "global.json"))
	ctx := context.Background()

	owner := &ApiService{Auth: auth.NewHolder(mgr), Globals: globals}
	first, err := owner.Setup(ctx, &gateonv1.SetupRequest{
		AdminUsername: "admin", AdminPassword: "first-password", PasetoSecret: strings.Repeat("a", 32),
	})
	if err != nil || !first.Success {
		t.Fatalf("first Setup: err=%v resp=%+v", err, first)
	}

	attacker := &ApiService{
		Auth:    auth.NewHolder(lockedAtSetupCheck{Manager: mgr, t: t, path: dbPath}),
		Globals: globals,
	}
	second, err := attacker.Setup(ctx, &gateonv1.SetupRequest{
		AdminUsername: "admin", AdminPassword: "attacker-password", PasetoSecret: strings.Repeat("b", 32),
	})
	if err != nil {
		t.Fatalf("second Setup: %v", err)
	}
	if second.Success {
		t.Errorf("Setup ran on a gateway that has an administrator because one read of the user table failed")
	}
	if _, _, err := mgr.Authenticate("admin", "attacker-password"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("the administrator's password was replaced: Authenticate(attacker-password) = %v", err)
	}
	if got := globals.Get(ctx).GetAuth().GetPasetoSecret(); got != strings.Repeat("a", 32) {
		t.Errorf("the PASETO secret was replaced by the caller's: %q", got)
	}
}
