// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/selfupdate/upgrade"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// fakeUpgrades stands in for *upgrade.Installer.
type fakeUpgrades struct {
	view     upgrade.View
	err      error
	installs []string
}

func (f *fakeUpgrades) View() upgrade.View { return f.view }

func (f *fakeUpgrades) Install(version, by string, automatic bool) error {
	if automatic {
		return errors.New("the API asked for an automatic install")
	}
	if f.err != nil {
		return f.err
	}
	f.installs = append(f.installs, version+" by "+by)
	return nil
}

func installService() (*ApiService, *fakeUpgrades) {
	up := &fakeUpgrades{}
	return &ApiService{Version: "1.8.2", Updates: newerRelease(), Upgrades: up}, up
}

func install() *gateonv1.InstallUpdateRequest {
	return &gateonv1.InstallUpdateRequest{Version: "1.8.3"}
}

// TestOnlyAnAdministratorInstallsARelease is the boundary the whole feature
// rests on: what this RPC starts ends with root replacing the gateway's
// binary. The RBAC table lets an operator reach it, as it lets them reach a
// global-settings save, so the role is checked here, in the one place every
// transport passes through.
func TestOnlyAnAdministratorInstallsARelease(t *testing.T) {
	s, up := installService()
	h := NewConnectHandler(s)
	denied := map[string]context.Context{
		"an operator":       as(auth.RoleOperator),
		"a viewer":          as(auth.RoleViewer),
		"nobody signed in":  context.Background(),
		"claims of no kind": context.WithValue(context.Background(), middleware.UserContextKey, "admin"),
	}
	for who, ctx := range denied {
		if _, err := s.InstallUpdate(ctx, install()); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s over gRPC: %v, want PermissionDenied", who, err)
		}
		if _, err := h.InstallUpdate(ctx, connect.NewRequest(install())); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s over Connect: %v, want PermissionDenied", who, err)
		}
	}
	if len(up.installs) != 0 {
		t.Fatalf("a refused caller started an install: %v", up.installs)
	}

	res, err := s.InstallUpdate(as(auth.RoleAdmin), install())
	if err != nil {
		t.Fatalf("an administrator over gRPC: %v", err)
	}
	if res.GetStatus().GetLatestVersion() != "1.8.3" || res.GetStatus().GetUpgrade() == nil {
		t.Errorf("the answer does not carry the status: %v", res.GetStatus())
	}
	if _, err := h.InstallUpdate(as(auth.RoleAdmin), connect.NewRequest(install())); err != nil {
		t.Fatalf("an administrator over Connect: %v", err)
	}
	want := []string{"1.8.3 by admin", "1.8.3 by admin"}
	if len(up.installs) != 2 || up.installs[0] != want[0] || up.installs[1] != want[1] {
		t.Fatalf("installs started: %v, want %v", up.installs, want)
	}
}

func TestARefusedInstallSaysWhichStateTheGatewayIsIn(t *testing.T) {
	cases := map[error]codes.Code{
		upgrade.ErrBusy:            codes.Aborted,
		upgrade.ErrBlocked:         codes.FailedPrecondition,
		upgrade.ErrNotOffered:      codes.FailedPrecondition,
		errors.New("disk on fire"): codes.Internal,
	}
	for cause, want := range cases {
		s, up := installService()
		up.err = cause
		_, err := s.InstallUpdate(as(auth.RoleAdmin), install())
		if status.Code(err) != want {
			t.Errorf("%v: answered %v, want %s", cause, err, want)
		}
		if want == codes.Internal && status.Convert(err).Message() != "the upgrade could not be started" {
			t.Errorf("an unexpected failure reached the caller verbatim: %q", status.Convert(err).Message())
		}
	}
}

func TestAGatewayBuiltWithoutAnInstallerCannotInstall(t *testing.T) {
	s := &ApiService{Version: "1.8.2", Updates: newerRelease()}
	if _, err := s.InstallUpdate(as(auth.RoleAdmin), install()); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v, want FailedPrecondition", err)
	}
	st, err := s.GetUpdateStatus(t.Context(), &gateonv1.GetUpdateStatusRequest{})
	if err != nil || st.GetStatus().GetUpgrade().GetBlocker() != gateonv1.UpgradeBlocker_UPGRADE_BLOCKER_ORCHESTRATED {
		t.Fatalf("the status offers an install nothing can perform: %v (%v)", st.GetStatus().GetUpgrade(), err)
	}
}

func TestTheStatusCarriesTheInstallAndItsHistory(t *testing.T) {
	s, up := installService()
	rolledBack := upgrade.Status{
		Phase: upgrade.PhaseRolledBack, Reason: upgrade.ReasonNotReady, Target: "1.8.3", Previous: "1.8.2",
		RequestedBy: "ada", RestoreDatabase: true, Nonce: "must-not-leave",
	}
	up.view = upgrade.View{
		Blocker: upgrade.BlockerNoHelper,
		Current: &rolledBack,
		History: []upgrade.Status{rolledBack, {Phase: upgrade.PhaseSucceeded, Target: "1.8.2", Previous: "1.8.1", Automatic: true}},
		Auto:    upgrade.Auto{Enabled: true, ByEnv: true, Scope: upgrade.ScopeMinor, Window: upgrade.Window{Start: 22 * 60, End: 90}},
	}
	for name, read := range map[string]func() *gateonv1.UpdateStatus{
		"GetUpdateStatus": func() *gateonv1.UpdateStatus {
			r, _ := s.GetUpdateStatus(t.Context(), &gateonv1.GetUpdateStatusRequest{})
			return r.GetStatus()
		},
		"CheckForUpdate": func() *gateonv1.UpdateStatus {
			r, _ := s.CheckForUpdate(t.Context(), &gateonv1.CheckForUpdateRequest{})
			return r.GetStatus()
		},
	} {
		u := read().GetUpgrade()
		cur := u.GetCurrent()
		if u.GetBlocker() != gateonv1.UpgradeBlocker_UPGRADE_BLOCKER_NO_HELPER ||
			cur.GetPhase() != gateonv1.UpgradePhase_UPGRADE_PHASE_ROLLED_BACK ||
			cur.GetReason() != gateonv1.UpgradeReason_UPGRADE_REASON_NOT_READY ||
			cur.GetTargetVersion() != "1.8.3" || cur.GetPreviousVersion() != "1.8.2" ||
			cur.GetRequestedBy() != "ada" || !cur.GetDatabaseRestored() {
			t.Errorf("%s: current = %v, blocker %v", name, cur, u.GetBlocker())
		}
		if len(u.GetHistory()) != 2 || !u.GetHistory()[1].GetAutomatic() ||
			u.GetHistory()[1].GetPhase() != gateonv1.UpgradePhase_UPGRADE_PHASE_SUCCEEDED {
			t.Errorf("%s: history = %v", name, u.GetHistory())
		}
		if !u.GetAutoInstall() || !u.GetAutoInstallByEnv() ||
			u.GetAutoInstallScope() != gateonv1.UpdateScope_UPDATE_SCOPE_MINOR ||
			u.GetWindowStart() != "22:00" || u.GetWindowEnd() != "01:30" {
			t.Errorf("%s: automatic install = %v", name, u)
		}
	}
}

func withWindow(start, end string) *gateonv1.GlobalConfig {
	return &gateonv1.GlobalConfig{Update: &gateonv1.UpdateConfig{
		AutoInstall: true, AutoInstallWindowStart: start, AutoInstallWindowEnd: end,
	}}
}

// TestAMaintenanceWindowThatCannotBeReadIsNotSaved: an unreadable window is
// skipped at run time in favour of the default one, so saving it with
// success would restart the gateway at an hour nobody chose.
func TestAMaintenanceWindowThatCannotBeReadIsNotSaved(t *testing.T) {
	stored := &gateonv1.GlobalConfig{}
	for _, bad := range [][2]string{{"02:00", ""}, {"", "04:00"}, {"2am", "4am"}, {"25:00", "26:00"}} {
		if err := validateGlobalSave(stored, withWindow(bad[0], bad[1])); status.Code(err) != codes.InvalidArgument {
			t.Errorf("window %q to %q saved: %v", bad[0], bad[1], err)
		}
	}
	for _, ok := range [][2]string{{"", ""}, {"02:00", "04:00"}, {"23:00", "01:00"}} {
		if err := validateGlobalSave(stored, withWindow(ok[0], ok[1])); err != nil {
			t.Errorf("window %q to %q refused: %v", ok[0], ok[1], err)
		}
	}
}

func TestOnlyAnAdministratorTurnsAutomaticInstallOn(t *testing.T) {
	s, _ := updateService(t)
	change := &gateonv1.UpdateGlobalConfigRequest{Config: withWindow("02:00", "04:00")}
	if _, err := s.UpdateGlobalConfig(as(auth.RoleOperator), change); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an operator switched automatic install on: %v", err)
	}
	if s.Globals.Get(t.Context()).GetUpdate().GetAutoInstall() {
		t.Fatal("the refused change was stored")
	}
	if _, err := s.UpdateGlobalConfig(as(auth.RoleAdmin), change); err != nil {
		t.Fatalf("an administrator's change: %v", err)
	}
	if got := s.Globals.Get(t.Context()).GetUpdate(); !got.GetAutoInstall() || got.GetAutoInstallWindowEnd() != "04:00" {
		t.Fatalf("the administrator's change was not stored: %v", got)
	}
}
