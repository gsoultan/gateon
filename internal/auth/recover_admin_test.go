// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The state a takeover leaves: the owner's account demoted and disabled, its
// password changed, a second factor enrolled by the attacker, and the
// attacker signed in on an account of their own. The dashboard is no way back
// from there, and before `gateon admin reset` the host had none either.
func TestRecoverAdministratorUndoesATakeover(t *testing.T) {
	m := newTestManager(t)
	ownerID := createUser(t, m, "rightful", ownerPass)
	enroll(t, m, ownerID, ownerPass)
	_, attackerToken := loginFixture(t, m, "mallory", "attacker-chosen-pass-1", RoleAdmin)
	if err := m.UpsertUser(&gateonv1.User{Id: ownerID, Username: "rightful", Password: "attacker-set-secret-2", Role: RoleViewer}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetUserDisabled(ownerID, true); err != nil {
		t.Fatal(err)
	}

	rec, err := m.RecoverAdministrator("rightful", false)
	if err != nil {
		t.Fatalf("RecoverAdministrator: %v", err)
	}
	if rec.UserID != ownerID || rec.Created || rec.Password == "" || rec.SessionsEnded != 2 {
		t.Fatalf("recovery = %+v, want the owner's account, a password, both accounts' sessions ended", rec)
	}
	row, err := m.loadLoginRow("rightful")
	if err != nil || row == nil {
		t.Fatalf("owner: %v", err)
	}
	if row.user.Role != RoleAdmin || row.user.Disabled || row.user.TwoFactorEnabled || !row.user.TwoFactorPending {
		t.Fatalf("owner after recovery = %+v, want an enabled administrator owing a new second factor", row.user)
	}
	if _, _, err := m.Authenticate("rightful", rec.Password, "192.0.2.1:1"); !errors.Is(err, ErrTwoFactorSetupRequired) {
		t.Fatalf("signing in with the new password: %v, want the second-factor enrolment it owes", err)
	}
	if _, err := m.VerifyToken(attackerToken); err == nil {
		t.Fatal("the attacker's session survived the recovery")
	}
}

func TestRecoverAdministratorCreatesOnlyWhenAsked(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.RecoverAdministrator("rescue", false); !errors.Is(err, ErrRecoveryNoSuchUser) {
		t.Fatalf("recovering a missing account without --create: %v", err)
	}
	rec, err := m.RecoverAdministrator("rescue", true)
	if err != nil || !rec.Created {
		t.Fatalf("recovering with create: %+v, %v", rec, err)
	}
	if !m.IsSetupDone() {
		t.Fatal("the gateway still has no administrator")
	}
}
