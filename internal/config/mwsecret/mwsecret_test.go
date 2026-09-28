// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mwsecret

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config/storedsecret"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
)

// placeholder is spelled out so a test cannot pass by agreeing with a changed
// constant.
const placeholder = "__gateon_redacted__"

func mw(id, typ string, cfg map[string]string) *gateonv1.Middleware {
	return &gateonv1.Middleware{Id: id, Name: id, Type: typ, Config: cfg}
}

// TestMaskShowsAWriterReferencesAndAReaderNothing: a reference names where a
// secret is held, which a writer needs in order to edit it; a reader gets the
// placeholder for it, as for every header and query value.
func TestMaskShowsAWriterReferencesAndAReaderNothing(t *testing.T) {
	live := mw("h", "headers", map[string]string{
		"set_request_Authorization": "$vault:secret/data/upstream#token",
		"set_request_X-Env":         "prod",
		"del_request_X-Debug":       "",
		"sts_seconds":               "31536000",
	})
	w := Mask(live).GetConfig()
	if w["set_request_Authorization"] != "$vault:secret/data/upstream#token" || w["set_request_X-Env"] != "prod" {
		t.Errorf("a writer read %v; want the reference and the plain header value as they are", w)
	}
	r := MaskForReader(live).GetConfig()
	if r["set_request_Authorization"] != placeholder || r["set_request_X-Env"] != placeholder {
		t.Errorf("a reader read %v; want the placeholder for the reference and for every header value", r)
	}
	if r["sts_seconds"] != "31536000" || r["del_request_X-Debug"] != "" {
		t.Errorf("a reader read %v; settings that set no value stay readable", r)
	}
}

// TestMaskDoesNotMutateTheLiveConfig is the incident case: the middlewares
// come from the live registry, and masking in place would delete the secrets
// from the running gateway on a read.
func TestMaskDoesNotMutateTheLiveConfig(t *testing.T) {
	cfg := map[string]string{"type": "basic", "users": "alice:pw1,bob:pw2", "key_AK1": "t1", "secret": "s"}
	want := maps.Clone(cfg)
	live := mw("a", "auth", cfg)
	for _, reader := range []bool{false, true} {
		_ = MaskAll([]*gateonv1.Middleware{live, nil}, !reader)
	}
	if !maps.Equal(live.Config, want) {
		t.Errorf("masking changed the live config to %v, want %v", live.Config, want)
	}
	if Mask(nil) != nil || len(MaskAll([]*gateonv1.Middleware{nil}, true)) != 0 {
		t.Error("a nil middleware must mask to nothing")
	}
}

// TestMaskShowsUsersByNameAndAPIKeysByFingerprint: the shapes the dashboard
// edits and sends back.
func TestMaskShowsUsersByNameAndAPIKeysByFingerprint(t *testing.T) {
	live := mw("a", "auth", map[string]string{"type": "basic", "users": " alice:pw1 , bob: ,, carol:pw3", "key_AK1": "t1"})
	got := Mask(live).GetConfig()
	if want := "alice:" + placeholder + ",bob:,carol:" + placeholder; got["users"] != want {
		t.Errorf("users read as %q, want %q", got["users"], want)
	}
	if got[apiKeyMarker("a", "AK1")] != "t1" || strings.Contains(strings.Join(slicesOf(got), " "), "AK1") {
		t.Errorf("the API key read as %v; want it only as its marker, labelled", got)
	}
	opaque := mw("b", "auth", map[string]string{"users": "enc:Zm9vYmFy"})
	if u := Mask(opaque).GetConfig()["users"]; u != placeholder {
		t.Errorf("an encrypted user list read as %q, want the placeholder: its parts are not users", u)
	}
}

func slicesOf(m map[string]string) []string {
	out := make([]string, 0, 2*len(m))
	for k, v := range m {
		out = append(out, k, v)
	}
	return out
}

// TestRestoreKeepsAStoredValueExactlyAsHeld: an encrypted value and a
// reference are kept as they are, not as what they resolve to.
func TestRestoreKeepsAStoredValueExactlyAsHeld(t *testing.T) {
	stored := mw("h", "hmac", map[string]string{"secret": "enc:c2VjcmV0", "other_secret": "$env:HMAC_OTHER"})
	update := mw("h", "hmac", map[string]string{"secret": placeholder, "other_secret": placeholder})
	if err := Restore(update, stored); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(update.Config, stored.Config) {
		t.Errorf("restored %v, want %v", update.Config, stored.Config)
	}
}

// TestRestoreRefusesWhatItCannotKeepAndChangesNothing: each refusal names the
// entry, and a refused update is left exactly as it was sent.
func TestRestoreRefusesWhatItCannotKeepAndChangesNothing(t *testing.T) {
	stored := mw("a", "auth", map[string]string{"type": "basic", "users": "alice:pw1,bob:pw2", "key_AK1": "t1"})
	cases := []struct {
		name, mentions string
		cfg            map[string]string
	}{
		{"a user whose password merely contains it", `"alice"`,
			map[string]string{"type": "basic", "users": "alice:x" + placeholder}},
		{"a user named with it", "is not it", map[string]string{"type": "basic", "users": placeholder + ":" + placeholder}},
		{"a malformed API key marker", "key_" + placeholder + "_zz",
			map[string]string{"type": "basic", "key_" + placeholder + "_zz": "t"}},
		{"an API key label holding it", "is not it",
			map[string]string{"type": "basic", apiKeyMarker("a", "AK1"): placeholder}},
		{"a user list that is not one", "users", map[string]string{"type": "basic", "users": "alice" + placeholder}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			update := mw("a", "auth", maps.Clone(c.cfg))
			err := Restore(update, stored)
			if err == nil || !strings.Contains(err.Error(), c.mentions) {
				t.Fatalf("Restore = %v, want a refusal naming %q", err, c.mentions)
			}
			if !maps.Equal(update.Config, c.cfg) {
				t.Errorf("a refused update was changed to %v", update.Config)
			}
		})
	}
}

// TestRestoreRefusesAnAPIKeySentAndKept: a map cannot hold one marker twice,
// but a client that knows a key can send it beside its marker; the key would
// get two tenants and one would be silently lost. Refused whichever of the two
// is read first -- the literal key sorts before the marker here, and after it
// in the second case.
func TestRestoreRefusesAnAPIKeySentAndKept(t *testing.T) {
	for _, apiKey := range []string{"AK1", "zz-after-the-marker"} {
		stored := mw("a", "auth", map[string]string{"type": "apikey", "key_" + apiKey: "t1"})
		update := mw("a", "auth", map[string]string{"type": "apikey", apiKeyMarker("a", apiKey): "t1", "key_" + apiKey: "t2"})
		if err := Restore(update, stored); err == nil || !strings.Contains(err.Error(), "key") {
			t.Errorf("Restore(%s) = %v, want the duplicate refused", apiKey, err)
		}
	}
}

// TestRestoreRefusesAPerUserPlaceholderForAnOpaqueList: a stored list that is
// a reference has no users to keep a password of.
func TestRestoreRefusesAPerUserPlaceholderForAnOpaqueList(t *testing.T) {
	stored := mw("a", "auth", map[string]string{"type": "basic", "users": "$env:BASIC_USERS"})
	update := mw("a", "auth", map[string]string{"type": "basic", "users": "alice:" + placeholder})
	if err := Restore(update, stored); err == nil || !strings.Contains(err.Error(), `"alice"`) {
		t.Errorf("Restore = %v, want alice refused", err)
	}
	whole := mw("a", "auth", map[string]string{"type": "basic", "users": placeholder})
	if err := Restore(whole, stored); err != nil || whole.Config["users"] != "$env:BASIC_USERS" {
		t.Errorf("Restore = %v, users %q; the whole placeholder keeps the whole stored value", err, whole.Config["users"])
	}
}

// TestRestoreBindsAForwardAuthSecretToItsAddress: the forward-auth address is
// where a request's credentials go; a kept secret-named value in its config is
// bound to it like any other destination.
func TestRestoreBindsAForwardAuthSecretToItsAddress(t *testing.T) {
	stored := mw("f", "forwardauth", map[string]string{"address": "https://auth.internal/check", "client_secret": "s"})
	update := mw("f", "forwardauth", map[string]string{"address": "https://collector.example/check",
		"client_secret": placeholder})
	if err := Restore(update, stored); !errors.Is(err, storedsecret.ErrMoved) {
		t.Errorf("Restore = %v, want ErrMoved", err)
	}
}

// TestFingerprintIsKeyed: an unkeyed hash of an API key would let anyone who
// reads middlewares test guesses offline. With GATEON_ENCRYPTION_KEY the key is
// derived from it (stable across restarts and gateways sharing it); without,
// it is random per process.
func TestFingerprintIsKeyed(t *testing.T) {
	saved := fingerprintKey
	t.Cleanup(func() { fingerprintKey = saved })

	unkeyed := sha256.Sum256([]byte("a\x00partner-2024"))
	if fingerprint("a", "partner-2024") == hex.EncodeToString(unkeyed[:8]) {
		t.Fatal("the fingerprint is an unkeyed hash of the API key")
	}
	t.Setenv("GATEON_ENCRYPTION_KEY", "a-shared-encryption-key-of-some-length")
	fingerprintKey = newFingerprintKey()
	seeded := fingerprint("a", "partner-2024")
	fingerprintKey = newFingerprintKey()
	if fingerprint("a", "partner-2024") != seeded {
		t.Error("with GATEON_ENCRYPTION_KEY set the fingerprint changed between two derivations; it must survive a restart")
	}
	t.Setenv("GATEON_ENCRYPTION_KEY", "")
	fingerprintKey = newFingerprintKey()
	if fingerprint("a", "partner-2024") == seeded {
		t.Error("without GATEON_ENCRYPTION_KEY the fingerprint equals the seeded one; the key must be random")
	}
	if fingerprint("a", "k") == fingerprint("b", "k") {
		t.Error("one API key has the same fingerprint in two middlewares; reuse across them would show")
	}
}

// TestMaskedMiddlewareIsACopy: proto.Clone, not a struct copy, so a field added
// to Middleware later is not dropped from the masked response only.
func TestMaskedMiddlewareIsACopy(t *testing.T) {
	live := mw("w", "wasm", map[string]string{"secret": "s"})
	live.WasmBlob = []byte{1, 2, 3}
	got := Mask(live)
	got.Config["x"] = "y"
	if _, leaked := live.Config["x"]; leaked || !proto.Equal(&gateonv1.Middleware{Id: "w", Name: "w", Type: "wasm",
		WasmBlob: []byte{1, 2, 3}, Config: map[string]string{"secret": placeholder, "x": "y"}}, got) {
		t.Errorf("Mask = %v, live = %v", got, live)
	}
}
