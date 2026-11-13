// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/selfupdate"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// fakeUpdates is a release checker that answers from memory and counts what
// it was asked.
type fakeUpdates struct {
	status         selfupdate.Status
	checks, kicks  int
	statusRequests int
}

func (f *fakeUpdates) Status() selfupdate.Status {
	f.statusRequests++
	return f.status
}

func (f *fakeUpdates) Check(context.Context) selfupdate.Status {
	f.checks++
	return f.status
}

func (f *fakeUpdates) Kick() { f.kicks++ }

func newerRelease() *fakeUpdates {
	return &fakeUpdates{status: selfupdate.Status{
		Current: "1.8.2", ReleaseBuild: true, Latest: "1.8.3", UpdateAvailable: true,
		Signature: selfupdate.SignatureVerified, State: selfupdate.StateOK, InstallKind: selfupdate.InstallSystemd,
	}}
}

// TestUpdateRPCsServeTheChecker: the status RPC reads what is known and asks
// nobody; only CheckForUpdate makes the gateway call out. Both on the RPC
// gRPC serves and on the Connect handler in front of it.
func TestUpdateRPCsServeTheChecker(t *testing.T) {
	up := newerRelease()
	s := &ApiService{Version: "1.8.2", Updates: up}

	got, err := s.GetUpdateStatus(t.Context(), &gateonv1.GetUpdateStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	st := got.GetStatus()
	if st.GetLatestVersion() != "1.8.3" || !st.GetUpdateAvailable() ||
		st.GetSignature() != gateonv1.UpdateSignature_UPDATE_SIGNATURE_VERIFIED ||
		st.GetInstallKind() != gateonv1.InstallKind_INSTALL_KIND_SYSTEMD {
		t.Errorf("GetUpdateStatus = %v", st)
	}
	if up.checks != 0 {
		t.Fatalf("reading the status asked the release source %d times", up.checks)
	}

	h := NewConnectHandler(s)
	viaConnect, err := h.GetUpdateStatus(t.Context(), connect.NewRequest(&gateonv1.GetUpdateStatusRequest{}))
	if err != nil || viaConnect.Msg.GetStatus().GetLatestVersion() != "1.8.3" || up.checks != 0 {
		t.Errorf("Connect GetUpdateStatus = %v, %v (checks %d)", viaConnect, err, up.checks)
	}

	checked, err := s.CheckForUpdate(t.Context(), &gateonv1.CheckForUpdateRequest{})
	if err != nil || checked.GetStatus().GetLatestVersion() != "1.8.3" || up.checks != 1 {
		t.Errorf("CheckForUpdate = %v, %v (checks %d, want 1)", checked, err, up.checks)
	}
	if _, err := h.CheckForUpdate(t.Context(), connect.NewRequest(&gateonv1.CheckForUpdateRequest{})); err != nil || up.checks != 2 {
		t.Errorf("Connect CheckForUpdate: %v (checks %d, want 2)", err, up.checks)
	}
}

// A service built without a checker asks nothing, so it must not read as
// "up to date" or as "not checked yet": it reports the check as off.
func TestUpdateRPCsWithoutACheckerReportTheCheckOff(t *testing.T) {
	s := &ApiService{Version: "1.8.2"}
	got, err := s.GetUpdateStatus(t.Context(), &gateonv1.GetUpdateStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	checked, err := s.CheckForUpdate(t.Context(), &gateonv1.CheckForUpdateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for name, st := range map[string]*gateonv1.UpdateStatus{"status": got.GetStatus(), "check": checked.GetStatus()} {
		if st.GetState() != gateonv1.UpdateCheckState_UPDATE_CHECK_STATE_DISABLED || st.GetCurrentVersion() != "1.8.2" ||
			st.GetUpdateAvailable() || st.GetLatestVersion() != "" {
			t.Errorf("%s with no checker = %v, want the check off", name, st)
		}
	}
}

func withSource(url string) *gateonv1.GlobalConfig {
	return &gateonv1.GlobalConfig{Update: &gateonv1.UpdateConfig{SourceUrl: url}}
}

// TestASavedReleaseSourceMustBeHTTPS: the release list decides which version
// the dashboard offers, so a source read over plain http:// lets anyone on
// the path decide that. Refused at save, on the path REST, Connect and gRPC
// share, so the setting never saves and then fails every check.
func TestASavedReleaseSourceMustBeHTTPS(t *testing.T) {
	stored := &gateonv1.GlobalConfig{}
	for _, bad := range []string{
		"http://mirror.example.com/releases",
		"https://user:secret@mirror.example.com/releases",
		"https://169.254.169.254/latest",
		"mirror.example.com",
	} {
		if err := validateGlobalSave(stored, withSource(bad)); status.Code(err) != codes.InvalidArgument {
			t.Errorf("release source %q saved: %v", bad, err)
		}
	}
	for _, ok := range []string{"", selfupdate.DefaultSource, "https://mirror.example.com/gateon", "http://127.0.0.1:8081/releases"} {
		if err := validateGlobalSave(stored, withSource(ok)); err != nil {
			t.Errorf("release source %q refused at save: %v", ok, err)
		}
	}
}

func updateService(t *testing.T) (*ApiService, *fakeUpdates) {
	t.Helper()
	t.Setenv("GATEON_ENCRYPTION_KEY", "")
	reg := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	if err := reg.Update(context.Background(), &gateonv1.GlobalConfig{
		Auth: &gateonv1.AuthConfig{Enabled: true, PasetoSecret: "0123456789abcdef0123456789abcdef"},
	}); err != nil {
		t.Fatal(err)
	}
	up := &fakeUpdates{}
	return NewApiService(ApiServiceConfig{Globals: reg, Updates: up}), up
}

// TestOnlyAnAdministratorChangesTheUpdateSettings: the update section names a
// host the gateway connects to on its own and believes about releases. An
// operator's save that changes it is refused whole, on the shared save path.
func TestOnlyAnAdministratorChangesTheUpdateSettings(t *testing.T) {
	s, _ := updateService(t)
	change := func() *gateonv1.UpdateGlobalConfigRequest {
		return &gateonv1.UpdateGlobalConfigRequest{Config: &gateonv1.GlobalConfig{
			Update: &gateonv1.UpdateConfig{CheckDisabled: true, SourceUrl: "https://mirror.example.com/releases"},
		}}
	}
	if _, err := s.UpdateGlobalConfig(as(auth.RoleOperator), change()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an operator's change to the update settings: %v, want PermissionDenied", err)
	}
	if got := s.Globals.Get(t.Context()).GetUpdate(); got.GetCheckDisabled() || got.GetSourceUrl() != "" {
		t.Fatalf("the refused change was stored: %v", got)
	}
	if _, err := s.UpdateGlobalConfig(as(auth.RoleAdmin), change()); err != nil {
		t.Fatalf("an administrator's change: %v", err)
	}
	if got := s.Globals.Get(t.Context()).GetUpdate(); !got.GetCheckDisabled() || got.GetSourceUrl() != "https://mirror.example.com/releases" {
		t.Fatalf("the administrator's change was not stored: %v", got)
	}
}

// TestAChangedUpdateSectionBringsTheCheckForward: a check switched back on,
// or pointed at a mirror, answers when it is saved rather than a day later.
// A save that leaves the section alone asks the release source nothing.
func TestAChangedUpdateSectionBringsTheCheckForward(t *testing.T) {
	s, up := updateService(t)
	save := func(c *gateonv1.GlobalConfig) {
		t.Helper()
		if _, err := s.UpdateGlobalConfig(as(auth.RoleAdmin), &gateonv1.UpdateGlobalConfigRequest{Config: c}); err != nil {
			t.Fatal(err)
		}
	}
	save(&gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true}})
	if up.kicks != 0 {
		t.Fatalf("a WAF save brought the release check forward %d times", up.kicks)
	}
	save(withSource("https://mirror.example.com/releases"))
	if up.kicks != 1 {
		t.Fatalf("changing the release source: %d kicks, want 1", up.kicks)
	}
	save(withSource("https://mirror.example.com/releases"))
	if up.kicks != 1 {
		t.Fatalf("saving the same source again: %d kicks, want still 1", up.kicks)
	}
}
