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
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestSetupIsClosedWithoutTheSetupToken: Setup runs before any account exists,
// on REST, Connect and gRPC alike, and asked for nothing -- whoever reached a
// fresh gateway first became its administrator, and could first have it probe
// any database address they liked. Without the token none of that happens: no
// probe, no account, no global.json.
func TestSetupIsClosedWithoutTheSetupToken(t *testing.T) {
	for name, token := range map[string]string{"no token": "", "wrong token": "not-the-setup-token"} {
		t.Run(name, func(t *testing.T) {
			svc, dir := firstRun(t)
			resp, err := svc.Setup(context.Background(), &gateonv1.SetupRequest{
				AdminUsername: "attacker", AdminPassword: "attacker-password", PasetoSecret: strings.Repeat("z", 32),
				SetupToken:  token,
				DatabaseUrl: filepath.Join(dir, "probed.db"),
			})
			if err != nil {
				t.Fatalf("Setup: %v", err)
			}
			if resp.GetSuccess() || resp.GetError() != auth.ErrSetupTokenRequired.Error() {
				t.Fatalf("Setup = %v, want the setup token refusal", resp)
			}
			// Opening a SQLite database creates its file: its absence is what
			// shows the refusal came before the probe.
			if _, err := os.Stat(filepath.Join(dir, "probed.db")); !os.IsNotExist(err) {
				t.Errorf("Setup without the token probed a database (stat err = %v)", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "global.json")); !os.IsNotExist(err) {
				t.Errorf("Setup without the token wrote global.json (stat err = %v)", err)
			}
			if auth.Available(svc.Auth) {
				t.Error("Setup without the token installed an auth manager")
			}
		})
	}
}

// A token that opened setup opens nothing after it, and its file goes with it.
func TestSetupRetiresTheSetupToken(t *testing.T) {
	svc, dir := firstRun(t)
	path, err := svc.SetupToken.Publish(dir)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	token := svc.SetupToken.Value()

	resp, err := svc.Setup(context.Background(), &gateonv1.SetupRequest{
		AdminUsername: "admin", AdminPassword: "first-password", PasetoSecret: strings.Repeat("a", 32),
		SetupToken: token,
	})
	if err != nil || !resp.GetSuccess() {
		t.Fatalf("Setup: err=%v resp=%v", err, resp)
	}
	if svc.SetupToken.Matches(token) {
		t.Error("the setup token still matches after setup completed")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the setup token file outlived setup (stat err = %v)", err)
	}
}
