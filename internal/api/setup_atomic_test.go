// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestASetupWhoseConfigWriteFailsLeavesSetupOpen: Setup created the
// administrator and installed the auth service, then failed to write
// global.json -- a config directory that is read-only, as the container image
// and Helm chart had it -- and answered failure with both in place. Where
// global.json already existed, the administrator alone closed setup for good:
// the operator, told setup failed, could not run it again once the directory
// was fixed, and global.json had neither the session key nor auth.enabled.
// A failed Setup must leave setup open, and a retry must succeed.
func TestASetupWhoseConfigWriteFailsLeavesSetupOpen(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through file modes, so the config cannot be made unwritable this way")
	}
	svc, dir := firstRun(t)
	ctx := context.Background()
	confDir := filepath.Join(dir, "conf")
	if err := os.Mkdir(confDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// A global.json that exists -- a seeded or mounted one -- in a directory
	// the gateway cannot write.
	svc.Globals = config.NewGlobalRegistry(filepath.Join(confDir, "global.json"))
	if err := svc.Globals.Update(ctx, &gateonv1.GlobalConfig{}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(confDir, "global.json")
	readOnly := func() {
		if err := os.Chmod(file, 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(confDir, 0o500); err != nil {
			t.Fatal(err)
		}
	}
	writable := func() {
		_ = os.Chmod(confDir, 0o750)
		_ = os.Chmod(file, 0o600)
	}
	readOnly()
	t.Cleanup(writable)
	req := &gateonv1.SetupRequest{
		AdminUsername: "admin", AdminPassword: "first-password", PasetoSecret: strings.Repeat("k", 32),
		SetupToken: svc.SetupToken.Value(),
	}

	if resp, err := svc.Setup(ctx, req); err != nil || resp.GetSuccess() {
		t.Fatalf("Setup over an unwritable config: err=%v resp=%v; want a reported failure", err, resp)
	}
	if got, err := svc.IsSetupRequired(ctx, &gateonv1.IsSetupRequiredRequest{}); err != nil || !got.GetRequired() {
		t.Errorf("a failed Setup closed setup (required=%v err=%v)", got.GetRequired(), err)
	}
	if mgr := openUsers(t, dir); mgr.IsSetupDone() {
		t.Error("a failed Setup left its administrator in the user database")
	}

	writable()
	if resp, err := svc.Setup(ctx, req); err != nil || !resp.GetSuccess() {
		t.Fatalf("Setup retried after the directory was fixed: err=%v resp=%v", err, resp)
	}
	if !svc.Globals.Get(ctx).GetAuth().GetEnabled() {
		t.Error("the retried Setup did not write auth.enabled")
	}
}

// openUsers opens the user database Setup writes in dir.
func openUsers(t *testing.T, dir string) *auth.Manager {
	t.Helper()
	m, err := auth.NewManager(filepath.Join(dir, "gateon.db"), strings.Repeat("k", 32), logger.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}
