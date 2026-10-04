// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/inits"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The identity the Helm chart's Secret supplies (ADR 0056).
const (
	podSessionKey = "chart-session-key-0123456789abcd" // 32 bytes
	podAuditKey   = "chart-audit-signature-key-0123456789abcdef0123456789abcdef"
	podPowSecret  = "chart-pow-secret-0123456789abcdef0123456789"
	podPassword   = "Adm1n-passphrase-xyz"
)

// pod is one gateway process as the chart starts it: its own volume, with
// global.json seeded from the chart's Secret, and the identity in its
// environment.
type pod struct {
	reg *config.GlobalRegistry
	mgr *auth.Manager
	svc *ApiService
	dir string
}

// startPod boots a gateway the way cmd/gateon does -- the registry over the
// seeded global.json, then inits.InitGlobalConfig -- on databaseURL.
func startPod(t *testing.T, databaseURL string) *pod {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "global.json")
	// What the chart's gateon.globalConfig renders with externalDatabase on.
	seed := fmt.Sprintf(`{"audit": {"enabled": true, "sign_entries": true}, "auth": {"database_url": %q}}`, databaseURL)
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := config.NewGlobalRegistry(path)
	if err := reg.LoadErr(); err != nil {
		t.Fatalf("load the seeded global.json: %v", err)
	}
	mgr := inits.InitGlobalConfig(path, reg)
	if mgr == nil {
		t.Fatal("the pod started with no auth manager")
	}
	t.Cleanup(func() { _ = mgr.Close() })
	return &pod{reg: reg, mgr: mgr, dir: dir, svc: &ApiService{
		Auth: auth.NewHolder(mgr), Globals: reg, SetupToken: newTestSetupToken(t),
	}}
}

// signInWithSecondFactor signs admin in on p with the password and a TOTP
// code, and returns the session token.
func (p *pod) signInWithSecondFactor(t *testing.T, id, secret string) string {
	t.Helper()
	_, _, err := p.mgr.Authenticate("admin", podPassword, "198.51.100.7")
	var step *auth.SecondStepError
	if !errors.As(err, &step) {
		t.Fatalf("password step: err = %v; want a second step owed", err)
	}
	at := time.Now()
	p.mgr.SetClock(func() time.Time { return at })
	code, err := totp.GenerateCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	ok, token, _, err := p.mgr.Verify2FA(step.Challenge, id, code)
	if err != nil || !ok || token == "" {
		t.Fatalf("second step: ok=%v err=%v", ok, err)
	}
	return token
}

// enrolSecondFactor turns 2FA on for id on p and returns the TOTP secret.
func (p *pod) enrolSecondFactor(t *testing.T, id string) string {
	t.Helper()
	enrolment, err := p.mgr.Setup2FA(id, podPassword)
	if err != nil {
		t.Fatalf("Setup2FA: %v", err)
	}
	code, err := totp.GenerateCode(enrolment.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, _, err := p.mgr.Verify2FA(enrolment.Challenge, id, code); err != nil || !ok {
		t.Fatalf("enrolling: ok=%v err=%v", ok, err)
	}
	return enrolment.Secret
}

// TestPodsWithTheChartsIdentityAreOneGateway is OPS-N1 as the review ran it:
// two gateways on one database, each on its own volume seeded from the chart,
// set up through one of them. Each generated its own session key -- setup
// stored the wizard's on the replica that ran it -- so a session from one got
// 401 on the other, a second factor enrolled on one answered 500 on the other
// ("stored under a different session key"), and with persistence off every
// restart was such a second gateway. With the identity in the environment,
// both use it, setup keeps it, and each accepts the other's sessions and second
// factors.
func TestPodsWithTheChartsIdentityAreOneGateway(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		checkPodsShareTheIdentity(t, filepath.Join(t.TempDir(), "shared.db"))
	})
	t.Run("postgres", func(t *testing.T) {
		checkPodsShareTheIdentity(t, scratchPostgres(t))
	})
}

func checkPodsShareTheIdentity(t *testing.T, databaseURL string) {
	t.Setenv("GATEON_ENCRYPTION_KEY", "")
	t.Setenv(config.SessionKeyEnv, podSessionKey)
	t.Setenv(config.AuditSignatureKeyEnv, podAuditKey)
	t.Setenv(config.PowSecretEnv, podPowSecret)
	a, b := startPod(t, databaseURL), startPod(t, databaseURL)

	// Set up through A with a key of the wizard's own, as the dashboard sends.
	resp, err := a.svc.Setup(context.Background(), &gateonv1.SetupRequest{
		AdminUsername: "admin", AdminPassword: podPassword, SetupToken: a.svc.SetupToken.Value(),
		PasetoSecret: "wizard-generated-key-0123456789a",
	})
	if err != nil || !resp.Success {
		t.Fatalf("Setup on A: err=%v resp=%+v", err, resp)
	}
	for name, p := range map[string]*pod{"A": a, "B": b} {
		gc := p.reg.Get(context.Background())
		if gc.GetAuth().GetPasetoSecret() != podSessionKey || gc.GetAudit().GetSignatureKey() != podAuditKey ||
			gc.GetSecurityAdvanced().GetPow().GetSecret() != podPowSecret {
			t.Errorf("pod %s is not on the environment's identity", name)
		}
	}
	assertStoredAsReferences(t, filepath.Join(a.dir, "global.json"))

	_, admin, err := a.mgr.Authenticate("admin", podPassword, "198.51.100.7")
	if err != nil {
		t.Fatalf("sign in on A: %v", err)
	}
	secret := a.enrolSecondFactor(t, admin.GetId())
	for _, tc := range []struct{ signIn, use *pod }{{a, b}, {b, a}} {
		token := tc.signIn.signInWithSecondFactor(t, admin.GetId(), secret)
		if _, err := tc.use.mgr.VerifyToken(token); err != nil {
			t.Errorf("a session from one pod is refused by the other: %v", err)
		}
	}
}

// assertStoredAsReferences requires global.json to name the identity by its
// variables, and to hold neither the values nor the wizard's key: a stored
// value would be one more copy of the secret, and the wizard's key a gateway of
// its own after the next restart.
func assertStoredAsReferences(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stored := string(raw)
	for _, env := range []string{config.SessionKeyEnv, config.AuditSignatureKeyEnv, config.PowSecretEnv} {
		if !strings.Contains(stored, "$env:"+env) {
			t.Errorf("global.json does not refer to %s:\n%s", env, stored)
		}
	}
	for _, leaked := range []string{podSessionKey, podAuditKey, podPowSecret, "wizard-generated-key"} {
		if strings.Contains(stored, leaked) {
			t.Errorf("global.json holds %q:\n%s", leaked, stored)
		}
	}
}

// scratchPostgres creates a database of this test's own on the server
// GATEON_TEST_POSTGRES_DSN names, and drops it afterwards. Setup needs a
// database with no administrator, which the module's shared one is not.
func scratchPostgres(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("GATEON_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEON_TEST_POSTGRES_DSN not set")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme == "" {
		t.Skipf("GATEON_TEST_POSTGRES_DSN is not a URL this test can derive a database from: %v", err)
	}
	admin, _, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("open %s: %v", u.Redacted(), err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	name := "gateon_ops_n1_" + hex.EncodeToString(suffix)
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Skipf("cannot create a scratch database: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)"); err != nil {
			t.Logf("drop scratch database %s: %v", name, err)
		}
	})
	u.Path = "/" + name
	return u.String()
}
