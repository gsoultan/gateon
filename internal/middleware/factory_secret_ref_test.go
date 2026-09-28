// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config/mwsecret"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// A middleware is written by an operator, and every field resolves
// $env:/$vault:/$aws-sm: references. Unconstrained, an operator could name any
// secret the process holds -- and read it back through a response header, or
// send it to a URL the same middleware names, without ever being an
// administrator. Two limits, both fail closed: a reference is honoured only in
// a field that holds a secret, and only when the host allow-listed it.

func TestFactoryRefusesASecretReferenceInANonSecretField(t *testing.T) {
	t.Setenv("GATEON_ENCRYPTION_KEY_TEST_TARGET", "the-encryption-key")
	// The host has allow-listed the reference, so only the field's kind refuses
	// it: a response header's value is echoed to the client, never used as a
	// credential, so a reference there would be an exfiltration path.
	t.Setenv(mwsecret.SecretRefsEnv, "$env:GATEON_ENCRYPTION_KEY_TEST_TARGET")
	f := NewFactory(nil, nil, nil, nil, t.TempDir())

	m := &gateonv1.Middleware{Id: "hdr-1", Type: "headers", Config: map[string]string{
		"set_response_X-Leak": "$env:GATEON_ENCRYPTION_KEY_TEST_TARGET",
	}}
	_, err := f.Create(m, "route-1")
	if err == nil || !strings.Contains(err.Error(), "field that holds a secret") {
		t.Fatalf("a secret reference in a plain response-header value built (err %v); it must be refused", err)
	}
	if err != nil && strings.Contains(err.Error(), "the-encryption-key") {
		t.Fatalf("the refusal leaked the resolved secret: %v", err)
	}
}

func TestFactoryRefusesASecretReferenceTheHostDidNotAllowList(t *testing.T) {
	t.Setenv("HMAC_TEST_SECRET", "a-real-signing-secret")
	t.Setenv(mwsecret.SecretRefsEnv, "$env:SOMETHING_ELSE")
	f := NewFactory(nil, nil, nil, nil, t.TempDir())

	m := &gateonv1.Middleware{Id: "hmac-1", Type: "hmac", Config: map[string]string{
		"secret": "$env:HMAC_TEST_SECRET",
	}}
	_, err := f.Create(m, "route-1")
	if err == nil || !strings.Contains(err.Error(), mwsecret.SecretRefsEnv) {
		t.Fatalf("a reference the host did not allow-list built (err %v); it must be refused naming %s",
			err, mwsecret.SecretRefsEnv)
	}
}

func TestFactoryResolvesAnAllowListedReferenceInASecretField(t *testing.T) {
	t.Setenv("HMAC_TEST_SECRET", "a-real-signing-secret")
	t.Setenv(mwsecret.SecretRefsEnv, "$env:HMAC_TEST_SECRET")
	f := NewFactory(nil, nil, nil, nil, t.TempDir())

	m := &gateonv1.Middleware{Id: "hmac-1", Type: "hmac", Config: map[string]string{
		"secret": "$env:HMAC_TEST_SECRET",
	}}
	if _, err := f.Create(m, "route-1"); err != nil {
		t.Fatalf("an allow-listed reference in a secret field did not build: %v", err)
	}
}

// A literal secret in a secret field is not a reference and is unaffected by
// the allow-list, whether or not one is set.
func TestFactoryBuildsALiteralSecretWithNoAllowList(t *testing.T) {
	t.Setenv(mwsecret.SecretRefsEnv, "")
	f := NewFactory(nil, nil, nil, nil, t.TempDir())

	m := &gateonv1.Middleware{Id: "hmac-1", Type: "hmac", Config: map[string]string{
		"secret": "a-real-signing-secret",
	}}
	if _, err := f.Create(m, "route-1"); err != nil {
		t.Fatalf("a literal secret was refused with no allow-list set: %v", err)
	}
}
