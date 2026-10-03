// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const (
	sessionKeyInForce = "0123456789abcdef0123456789abcdef"
	sessionKeyNext    = "fedcba9876543210fedcba9876543210"
)

// sessionKeyFixture is a gateway whose saved session key is the one its auth
// manager signs with, and a session signed with it.
func sessionKeyFixture(t *testing.T) (*ApiService, *auth.Manager, string, string) {
	t.Helper()
	dir := t.TempDir()
	m, err := auth.NewManager(filepath.Join(dir, "auth.db"), sessionKeyInForce, logger.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if err := m.UpsertUser(&gateonv1.User{Username: "admin", Password: "correct-horse-battery", Role: auth.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	token, _, err := m.Authenticate("admin", "correct-horse-battery", "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "global.json")
	reg := config.NewGlobalRegistry(path)
	if err := reg.Update(context.Background(), &gateonv1.GlobalConfig{
		Auth: &gateonv1.AuthConfig{Enabled: true, PasetoSecret: sessionKeyInForce},
	}); err != nil {
		t.Fatal(err)
	}
	return &ApiService{Globals: reg, Auth: m}, m, token, path
}

func saveSessionKey(svc *ApiService, key string) error {
	_, err := svc.UpdateGlobalConfig(withRole(auth.RoleAdmin), &gateonv1.UpdateGlobalConfigRequest{
		Config: &gateonv1.GlobalConfig{Auth: &gateonv1.AuthConfig{Enabled: true, PasetoSecret: key}},
	})
	return err
}

// TestUpdateGlobalConfigPutsANewSessionKeyInForceAtOnce: a key saved in
// Settings used to be written to global.json and nowhere else, so every
// session signed with the key being replaced -- the leaked one, if that is why
// it was rotated -- went on working until somebody restarted the gateway.
func TestUpdateGlobalConfigPutsANewSessionKeyInForceAtOnce(t *testing.T) {
	svc, m, token, _ := sessionKeyFixture(t)
	if err := saveSessionKey(svc, sessionKeyNext); err != nil {
		t.Fatalf("saving a new session key: %v", err)
	}
	if _, err := m.VerifyToken(token); err == nil {
		t.Fatal("a session signed with the replaced key still verifies: the new key was saved but not put in force")
	}
}

// TestUpdateGlobalConfigRefusesASessionKeyTheGatewayCannotStartWith: under 32
// bytes the next start exits, so it is refused before anything changes.
func TestUpdateGlobalConfigRefusesASessionKeyTheGatewayCannotStartWith(t *testing.T) {
	svc, m, token, _ := sessionKeyFixture(t)
	err := saveSessionKey(svc, "too-short")
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("saving a short key = %v; want InvalidArgument", err)
	}
	if got := svc.Globals.Get(context.Background()).GetAuth().GetPasetoSecret(); got != sessionKeyInForce {
		t.Fatalf("the refused key was stored: %q", got)
	}
	if _, err := m.VerifyToken(token); err != nil {
		t.Fatalf("a refused key ended the session: %v", err)
	}
}

// TestUpdateGlobalConfigRefusesRotatingASessionKeyFromTheEnvironment: with the
// key from GATEON_SESSION_KEY (a Helm install, ADR 0056) a key rotated in
// Settings was in force on this pod only, written over the reference on this
// volume only, and the second factors re-encrypted under it unreadable after
// the next start that read the reference again.
func TestUpdateGlobalConfigRefusesRotatingASessionKeyFromTheEnvironment(t *testing.T) {
	t.Setenv(config.SessionKeyEnv, sessionKeyInForce)
	svc, m, token, path := sessionKeyFixture(t)
	err := saveSessionKey(svc, sessionKeyNext)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("rotating an environment-supplied key = %v; want InvalidArgument", err)
	}
	if _, err := m.VerifyToken(token); err != nil {
		t.Fatalf("a refused rotation ended the session: %v", err)
	}
	if raw, err := os.ReadFile(path); err != nil || !strings.Contains(string(raw), "$env:"+config.SessionKeyEnv) {
		t.Fatalf("global.json no longer refers to %s (err %v):\n%s", config.SessionKeyEnv, err, raw)
	}
	// Saving the settings as a writer reads them -- the reference -- is not a
	// rotation, and still saves.
	if err := saveSessionKey(svc, "$env:"+config.SessionKeyEnv); err != nil {
		t.Fatalf("saving the reference back: %v", err)
	}
}

// TestUpdateGlobalConfigKeepsTheSessionKeyWhenTheSaveFails: the key in force
// and the saved key must not part ways -- a new key in force that the next
// start does not read would end every session twice.
func TestUpdateGlobalConfigKeepsTheSessionKeyWhenTheSaveFails(t *testing.T) {
	svc, m, token, path := sessionKeyFixture(t)
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if err := saveSessionKey(svc, sessionKeyNext); err == nil {
		t.Skip("global.json stayed writable (running as root?); cannot make the save fail")
	}
	if _, err := m.VerifyToken(token); err != nil {
		t.Fatalf("the save failed, yet the new key is in force: %v", err)
	}
}
