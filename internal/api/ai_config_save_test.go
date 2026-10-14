// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config/storedsecret"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The AI provider settings are saved through UpdateGlobalConfig, which REST
// (PUT /v1/global), Connect and gRPC share, so these hold on every transport
// (ADR 0069).

func saveAI(t *testing.T, role string, edit func(*gateonv1.AIConfig)) (*ApiService, error) {
	t.Helper()
	svc := &ApiService{Globals: globalRegistryWithSecrets(t)}
	update := proto.Clone(svc.Globals.Get(withRole(role))).(*gateonv1.GlobalConfig)
	storedsecret.Mask(update) // what the dashboard read, and sends back
	edit(update.Ai)
	_, err := svc.UpdateGlobalConfig(withRole(role), &gateonv1.UpdateGlobalConfigRequest{Config: update})
	return svc, err
}

func TestAISaveRefusesAProviderItCouldNeverCall(t *testing.T) {
	_, err := saveAI(t, auth.RoleAdmin, func(a *gateonv1.AIConfig) { a.BaseUrl = "http://api.example.com" })
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("plain-http provider saved: err = %v, want InvalidArgument", err)
	}
}

// Where findings and log lines go is administrator-only: an operator who
// could set it could read the gateway's logs from a server of their own.
func TestAISettingsAreAdministratorOnly(t *testing.T) {
	_, err := saveAI(t, auth.RoleOperator, func(a *gateonv1.AIConfig) { a.ShareLogLines = true })
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator changed the AI settings: err = %v, want PermissionDenied", err)
	}
}

// The stored key goes only where it was entered for: a save that keeps the
// placeholder and points the provider elsewhere is refused.
func TestAIKeyIsNotKeptForANewDestination(t *testing.T) {
	_, err := saveAI(t, auth.RoleAdmin, func(a *gateonv1.AIConfig) { a.BaseUrl = "https://collector.example" })
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("stored key re-pointed: err = %v, want InvalidArgument", err)
	}
	svc, err := saveAI(t, auth.RoleAdmin, func(a *gateonv1.AIConfig) { a.Model = "claude-haiku-5-5" })
	if err != nil {
		t.Fatalf("an unrelated change with the placeholder: %v", err)
	}
	if got := svc.Globals.Get(withRole(auth.RoleAdmin)).GetAi(); got.GetApiKey() != "sk-ant-AI-KEY" || got.GetModel() != "claude-haiku-5-5" {
		t.Errorf("stored AI settings = %+v; want the key kept and the model changed", got)
	}
}
