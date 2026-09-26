// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestSetupRefusesToRunAgainOnceAnAdministratorExists.
//
// Setup is served before authentication, so the only thing keeping it from
// being re-run against a configured gateway is IsSetupRequired. That answered
// "required" whenever the stored PASETO secret was empty -- a state a
// global-config write can produce, and one that ActionWrite on ResourceGlobal
// (an operator, not only an administrator) is enough to reach. Setup then
// reuses the id of the existing administrator with the requested username and
// overwrites their password, so the sequence is an operator becoming admin,
// or anyone who can reach the management port becoming admin once an operator
// has saved settings with the field blank.
func TestSetupRefusesToRunAgainOnceAnAdministratorExists(t *testing.T) {
	tmp := t.TempDir()
	mgr, err := auth.NewManager(filepath.Join(tmp, "auth.db"), strings.Repeat("k", 32), logger.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	svc := &ApiService{
		Auth:       auth.NewHolder(mgr),
		Globals:    config.NewGlobalRegistry(filepath.Join(tmp, "global.json")),
		SetupToken: newTestSetupToken(t),
	}
	ctx := context.Background()

	first, err := svc.Setup(ctx, &gateonv1.SetupRequest{
		AdminUsername: "admin", AdminPassword: "first-password", PasetoSecret: strings.Repeat("a", 32),
		SetupToken: svc.SetupToken.Value(),
	})
	if err != nil || !first.Success {
		t.Fatalf("first Setup: err=%v resp=%+v", err, first)
	}

	// A global-config save that leaves the secret blank.
	conf := svc.Globals.Get(ctx)
	conf.Auth.PasetoSecret = ""
	if err := svc.Globals.Update(ctx, conf); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// A token that still matches -- Setup retired the first -- so that only the
	// setup-required guard can refuse: this is that guard's test.
	svc.SetupToken = newTestSetupToken(t)
	second, err := svc.Setup(ctx, &gateonv1.SetupRequest{
		AdminUsername: "admin", AdminPassword: "attacker-password", PasetoSecret: strings.Repeat("b", 32),
		SetupToken: svc.SetupToken.Value(),
	})
	if err != nil {
		t.Fatalf("second Setup: %v", err)
	}
	if second.Success {
		t.Errorf("Setup ran a second time on a gateway that already has an administrator")
	}
	if _, _, err := mgr.Authenticate("admin", "attacker-password"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("the administrator's password was replaced by the second Setup: Authenticate(attacker-password) = %v", err)
	}
	if _, _, err := mgr.Authenticate("admin", "first-password"); err != nil {
		t.Errorf("the original administrator password no longer works: %v", err)
	}
}
