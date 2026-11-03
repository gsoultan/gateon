// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/telemetry/threatarchive"
	"github.com/gsoultan/gateon/internal/telemetry/tracearchive"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// archiveOnRetentionField is the field's name in a refusal. Spelled out, so
// the test cannot pass by agreeing with a renamed field.
const archiveOnRetentionField = "log.archive_on_retention"

// requireArchivesEverything checks what retention will actually do, read the
// way each retention pass reads it, not what was stored: a setting that saved
// and was never read is the defect this guards against.
func requireArchivesEverything(t *testing.T, transport string, want bool) {
	t.Helper()
	if got := config.ArchiveOnRetention(); got != want {
		t.Errorf("after %s, archive everything resolves to %v, want %v", transport, got, want)
	}
	if got := tracearchive.CurrentSettings().Enabled; got != want {
		t.Errorf("after %s, the trace archive is enabled=%v, want %v", transport, got, want)
	}
	if got := threatarchive.CurrentSettings().Enabled; got != want {
		t.Errorf("after %s, the security threat archive is enabled=%v, want %v", transport, got, want)
	}
}

func clearArchiveEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{config.EnvArchiveOnRetention, tracearchive.EnvEnabled, threatarchive.EnvEnabled} {
		t.Setenv(v, "")
	}
}

// TestArchiveOnRetentionTakesEffectOnEveryTransport: the dashboard's switch is
// PUT /v1/global with log.archiveOnRetention, the JSON the dashboard sends;
// gRPC is UpdateGlobalConfig. An administrator's save on either turns every
// archive on and off again, with the per-log switches left off throughout.
func TestArchiveOnRetentionTakesEffectOnEveryTransport(t *testing.T) {
	t.Run("REST", func(t *testing.T) {
		clearArchiveEnv(t)
		a, _ := newAdminAPI(t)
		requireArchivesEverything(t, "start", false)
		for _, on := range []bool{true, false} {
			conf := a.readGlobalJSON(t)
			section(t, conf, "log")["archiveOnRetention"] = on
			if code, body := a.putGlobalJSON(t, conf); code != http.StatusOK {
				t.Fatalf("PUT /v1/global with archiveOnRetention=%v: %d %s", on, code, body)
			}
			if got, _ := section(t, a.readGlobalJSON(t), "log")["archiveOnRetention"].(bool); got != on {
				t.Errorf("GET /v1/global reads archiveOnRetention=%v after saving %v", got, on)
			}
			requireArchivesEverything(t, "a REST save", on)
		}
	})

	t.Run("gRPC", func(t *testing.T) {
		clearArchiveEnv(t)
		a, _ := newAdminAPI(t)
		requireArchivesEverything(t, "start", false)
		for _, on := range []bool{true, false} {
			resp, err := a.grpc.GetGlobalConfig(context.Background(), &gateonv1.GetGlobalConfigRequest{})
			if err != nil {
				t.Fatalf("gRPC GetGlobalConfig: %v", err)
			}
			conf := resp.GetConfig()
			if conf.Log == nil {
				conf.Log = &gateonv1.LogConfig{}
			}
			conf.Log.ArchiveOnRetention = on
			if _, err := a.grpc.UpdateGlobalConfig(context.Background(), &gateonv1.UpdateGlobalConfigRequest{Config: conf}); err != nil {
				t.Fatalf("gRPC UpdateGlobalConfig with archive_on_retention=%v: %v", on, err)
			}
			resp, err = a.grpc.GetGlobalConfig(context.Background(), &gateonv1.GetGlobalConfigRequest{})
			if err != nil {
				t.Fatal(err)
			}
			if got := resp.GetConfig().GetLog().GetArchiveOnRetention(); got != on {
				t.Errorf("gRPC GetGlobalConfig reads archive_on_retention=%v after saving %v", got, on)
			}
			requireArchivesEverything(t, "a gRPC save", on)
		}
	})
}

// TestOperatorCannotChangeArchiveOnRetention: the switch archives audit
// entries too, so switching it off lets retention delete an audit trail it
// used to keep. It is administrator-only, as audit_log_retention_days is, on
// both transports, and a refused save changes nothing.
func TestOperatorCannotChangeArchiveOnRetention(t *testing.T) {
	t.Run("REST", func(t *testing.T) {
		clearArchiveEnv(t)
		a, _ := newAPIAs(t, operatorClaims)
		live, file := a.snapshot(t)
		conf := a.readGlobalJSON(t)
		section(t, conf, "log")["archiveOnRetention"] = true
		code, body := a.putGlobalJSON(t, conf)
		if code != http.StatusForbidden || !strings.Contains(body, archiveOnRetentionField) {
			t.Fatalf("an operator's save of archiveOnRetention got %d %s, want 403 naming %s", code, body, archiveOnRetentionField)
		}
		a.requireUnchanged(t, "a refused REST save", live, file)
		requireArchivesEverything(t, "a refused REST save", false)
	})

	t.Run("gRPC", func(t *testing.T) {
		clearArchiveEnv(t)
		a, _ := newAPIAs(t, operatorClaims)
		live, file := a.snapshot(t)
		resp, err := a.grpc.GetGlobalConfig(context.Background(), &gateonv1.GetGlobalConfigRequest{})
		if err != nil {
			t.Fatal(err)
		}
		conf := resp.GetConfig()
		if conf.Log == nil {
			conf.Log = &gateonv1.LogConfig{}
		}
		conf.Log.ArchiveOnRetention = true
		_, err = a.grpc.UpdateGlobalConfig(context.Background(), &gateonv1.UpdateGlobalConfigRequest{Config: conf})
		if status.Code(err) != codes.PermissionDenied || !strings.Contains(status.Convert(err).Message(), archiveOnRetentionField) {
			t.Fatalf("an operator's gRPC save of archive_on_retention got %v, want PermissionDenied naming %s", err, archiveOnRetentionField)
		}
		a.requireUnchanged(t, "a refused gRPC save", live, file)
		requireArchivesEverything(t, "a refused gRPC save", false)
	})
}
