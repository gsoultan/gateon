// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const (
	envSessionKey = "env-session-key-0123456789abcdef"
	envAuditKey   = "env-audit-signature-key-0123456789abcdef"
	envPowSecret  = "env-pow-secret-0123456789abcdef"
)

func setIdentityEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GATEON_ENCRYPTION_KEY", "")
	t.Setenv(SessionKeyEnv, envSessionKey)
	t.Setenv(AuditSignatureKeyEnv, envAuditKey)
	t.Setenv(PowSecretEnv, envPowSecret)
}

func identityOf(c *gateonv1.GlobalConfig) [3]string {
	return [3]string{
		c.GetAuth().GetPasetoSecret(), c.GetAudit().GetSignatureKey(), c.GetSecurityAdvanced().GetPow().GetSecret(),
	}
}

// TestIdentityComesFromTheEnvironmentOnAFreshVolume covers a gateway with no
// global.json, and one whose global.json -- the chart's seed -- names no
// identity: both are what every start on a fresh volume is. Each used to
// generate its own session key, audit key and proof-of-work secret, so two
// replicas, or one pod before and after a restart without persistence, were
// two gateways (OPS-N1, ADR 0056).
func TestIdentityComesFromTheEnvironmentOnAFreshVolume(t *testing.T) {
	setIdentityEnv(t)
	want := [3]string{envSessionKey, envAuditKey, envPowSecret}
	for name, seed := range map[string]string{
		"no global.json":      "",
		"the chart's seed":    `{"audit": {"enabled": true, "sign_entries": true}, "auth": {"database_url": "x.db"}}`,
		"an empty audit/auth": `{"audit": {}, "auth": {}}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "global.json")
			if seed != "" {
				if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			reg := NewGlobalRegistry(path)
			if got := identityOf(reg.Get(t.Context())); got != want {
				t.Fatalf("identity = %q; want the environment's %q", got, want)
			}
			if over := identityOverrides(reg.refs, reg.Get(t.Context())); len(over) != 0 {
				t.Errorf("an environment-supplied identity is reported as overridden: %v", over)
			}
			// What setup and every later save write: the references, never the
			// values -- or the next start on this volume is a gateway of its own.
			if err := reg.Update(t.Context(), proto.Clone(reg.Get(t.Context())).(*gateonv1.GlobalConfig)); err != nil {
				t.Fatalf("Update: %v", err)
			}
			stored := onDisk(t, path)
			for _, env := range []string{SessionKeyEnv, AuditSignatureKeyEnv, PowSecretEnv} {
				if !strings.Contains(stored, `"$env:`+env+`"`) {
					t.Errorf("global.json does not refer to %s:\n%s", env, stored)
				}
			}
			for _, v := range want {
				if strings.Contains(stored, v) {
					t.Errorf("global.json holds the value %q:\n%s", v, stored)
				}
			}
		})
	}
}

// TestAnExistingInstallKeepsItsOwnIdentity: a global.json that names its own
// keys is an install whose sessions, second factors and audit chain were made
// with them. The chart's new Secret must not replace them on upgrade -- a new
// audit key would fail the stored chain's verification -- so the file wins,
// and the gateway says the environment's are not in use.
func TestAnExistingInstallKeepsItsOwnIdentity(t *testing.T) {
	setIdentityEnv(t)
	own := [3]string{"own-session-key-0123456789abcdef0", "own-audit-key", "own-pow-secret-0123456789"}
	path := filepath.Join(t.TempDir(), "global.json")
	body := `{"auth": {"paseto_secret": "` + own[0] + `"}, "audit": {"signature_key": "` + own[1] +
		`"}, "security_advanced": {"pow": {"secret": "` + own[2] + `"}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := NewGlobalRegistry(path)
	if got := identityOf(reg.Get(t.Context())); got != own {
		t.Fatalf("identity = %q; want global.json's own %q", got, own)
	}
	over := identityOverrides(reg.refs, reg.Get(t.Context()))
	if len(over) != 3 {
		t.Fatalf("overridden identity variables = %v; want all three named", over)
	}
}

// TestAnAuditSignatureKeyMayBeAReference: the audit chain's key had no
// reference support, so it could only live in global.json, on one volume.
func TestAnAuditSignatureKeyMayBeAReference(t *testing.T) {
	t.Setenv("GATEON_TEST_AUDIT_KEY_REF", "audit-key-from-a-reference")
	path := filepath.Join(t.TempDir(), "global.json")
	if err := os.WriteFile(path, []byte(`{"audit": {"signature_key": "$env:GATEON_TEST_AUDIT_KEY_REF"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := NewGlobalRegistry(path)
	if err := reg.LoadErr(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := reg.Get(t.Context()).GetAudit().GetSignatureKey(); got != "audit-key-from-a-reference" {
		t.Fatalf("audit.signature_key = %q; want the value the reference names", got)
	}
	if got := reg.WithSecretReferences(reg.Get(t.Context())).GetAudit().GetSignatureKey(); got != "$env:GATEON_TEST_AUDIT_KEY_REF" {
		t.Fatalf("a writer reads audit.signature_key as %q; want the reference", got)
	}
}
