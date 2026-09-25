// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestConnectGetGlobalConfigShowsSecretReferences is the Connect side of the
// Settings round trip: a caller who may write the config reads a referenced
// secret as its reference, so saving it back stores the reference, not the
// secret. The context carries no claims, which is how the service reads auth
// being off -- a writer.
func TestConnectGetGlobalConfigShowsSecretReferences(t *testing.T) {
	t.Setenv("GATEON_TEST_API_REF_4417", "resolved-api-secret")
	path := filepath.Join(t.TempDir(), "global.json")
	if err := os.WriteFile(path, []byte(`{"auth": {"paseto_secret": "$env:GATEON_TEST_API_REF_4417"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &ApiService{Globals: config.NewGlobalRegistry(path)}
	resp, err := s.GetGlobalConfig(t.Context(), &gateonv1.GetGlobalConfigRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.GetConfig().GetAuth().GetPasetoSecret(); got != "$env:GATEON_TEST_API_REF_4417" {
		t.Fatalf("GetGlobalConfig handed a writer %q, want the reference", got)
	}
}
