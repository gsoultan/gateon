// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/security"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func clamavService(t *testing.T) *ApiService {
	t.Helper()
	t.Setenv("GATEON_ENCRYPTION_KEY", "")
	reg := config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	stored := &gateonv1.GlobalConfig{
		Auth: &gateonv1.AuthConfig{Enabled: true, PasetoSecret: "0123456789abcdef0123456789abcdef"},
		Waf:  &gateonv1.WafConfig{Enabled: true, Clamav: &gateonv1.ClamavConfig{}},
	}
	if err := reg.Update(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	return &ApiService{Globals: reg, ClamAVManager: security.NewClamAVManager(stored.GetWaf().GetClamav())}
}

// TestOnlyAnAdministratorInstallsOrRemovesClamAV: InstallClamav runs docker or
// a package manager on the gateway's own host and stores the mode it was
// asked for. global:write, which the operator role holds, was the only thing
// it asked of the caller, so an operator could start a container on the host
// while the same change made through a save of the settings is refused. The
// refusal comes before anything is stored or run.
func TestOnlyAnAdministratorInstallsOrRemovesClamAV(t *testing.T) {
	for _, caller := range []struct {
		name string
		ctx  context.Context
	}{
		{"operator", as(auth.RoleOperator)},
		{"viewer", as(auth.RoleViewer)},
		{"unreadable claims", context.WithValue(context.Background(), middleware.UserContextKey, "not-claims")},
	} {
		t.Run(caller.name, func(t *testing.T) {
			s := clamavService(t)
			before := proto.Clone(s.Globals.Get(t.Context()))

			_, err := s.InstallClamav(caller.ctx, &gateonv1.InstallClamavRequest{
				Mode: gateonv1.ClamavConfig_INSTALLATION_MODE_DOCKER,
			})
			if status.Code(err) != codes.PermissionDenied {
				t.Errorf("InstallClamav: err = %v, want PermissionDenied", err)
			}
			_, err = s.UninstallClamav(caller.ctx, &gateonv1.UninstallClamavRequest{})
			if status.Code(err) != codes.PermissionDenied {
				t.Errorf("UninstallClamav: err = %v, want PermissionDenied", err)
			}
			if after := s.Globals.Get(t.Context()); !proto.Equal(before, after) {
				t.Errorf("a refused install changed the configuration:\nbefore %v\nafter  %v", before, after)
			}
		})
	}
}

// TestTheHostAdminRuleAdmitsWhoTheSaveAdmits is the control: the rule is the
// one a save of the settings applies, so an administrator passes, and so does
// a request nobody authenticated when authentication is off by configuration.
// It is asked of the rule and not of the RPC, because past the rule the RPC
// runs docker.
func TestTheHostAdminRuleAdmitsWhoTheSaveAdmits(t *testing.T) {
	s := clamavService(t)
	if err := s.requireHostAdmin(as(auth.RoleAdmin)); err != nil {
		t.Errorf("an administrator was refused: %v", err)
	}
	// Auth is enabled in the stored configuration but no auth service is
	// available: the plane is open, as it is before Setup has run.
	if err := s.requireHostAdmin(context.Background()); err != nil {
		t.Errorf("an open management plane was refused: %v", err)
	}
}

// TestASavedClamAVImageIsAnImageReference: the image name becomes an argument
// of `docker run`. One that starts with a dash is read by docker as an option.
func TestASavedClamAVImageIsAnImageReference(t *testing.T) {
	withImage := func(image string) *gateonv1.GlobalConfig {
		return &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Clamav: &gateonv1.ClamavConfig{DockerImage: image}}}
	}
	stored := &gateonv1.GlobalConfig{}
	for _, bad := range []string{"--privileged", "-v=/:/host", "clamav/clamav --privileged", "clamav;id"} {
		if err := validateGlobalSave(stored, withImage(bad)); status.Code(err) != codes.InvalidArgument {
			t.Errorf("image %q saved: %v", bad, err)
		}
	}
	for _, ok := range []string{"", "clamav/clamav:1.4", "registry.example:5000/sec/clamav@sha256:0123abcd"} {
		if err := validateGlobalSave(stored, withImage(ok)); err != nil {
			t.Errorf("image %q refused at save: %v", ok, err)
		}
	}
}
