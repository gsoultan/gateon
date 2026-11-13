// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/selfupdate"
)

// bench is a tool with its process replaced: an environment map, the trusted
// keys as a slice, and its output captured.
type bench struct {
	tool
	env     map[string]string
	trusted []ed25519.PublicKey
	out     bytes.Buffer
	errs    bytes.Buffer
	dir     string
}

func newBench(t *testing.T) *bench {
	t.Helper()
	b := &bench{env: map[string]string{}, dir: t.TempDir()}
	b.tool = tool{
		getenv: func(k string) string { return b.env[k] },
		keys:   func() []ed25519.PublicKey { return b.trusted },
		stdout: &b.out,
		stderr: &b.errs,
	}
	return b
}

func (b *bench) path(name string) string { return filepath.Join(b.dir, name) }

// keygen runs keygen and returns the private key file's content and the
// public key it printed.
func (b *bench) keygen(t *testing.T) (private string, public ed25519.PublicKey) {
	t.Helper()
	b.out.Reset()
	file := b.path("release.key")
	if err := b.run([]string{"keygen", "-out", file}); err != nil {
		t.Fatal(err)
	}
	keys, err := selfupdate.ParseKeys(b.out.Bytes())
	if err != nil || len(keys) != 1 {
		t.Fatalf("keygen printed %q, which release_keys.txt cannot hold: %v", b.out.String(), err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw), keys[0]
}

func (b *bench) checksums(t *testing.T, version string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(version))
	line := hex.EncodeToString(sum[:]) + "  gateon_" + version + "_linux_amd64.tar.gz\n"
	file := b.path("checksums.txt")
	if err := os.WriteFile(file, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

// TestAKeygenKeySignsWhatAGatewayVerifies is the whole path a release takes:
// the key keygen writes, once its public line is trusted, signs a list that
// verifies the way a gateway verifies it.
func TestAKeygenKeySignsWhatAGatewayVerifies(t *testing.T) {
	b := newBench(t)
	private, public := b.keygen(t)
	b.env[envKey] = private
	b.trusted = []ed25519.PublicKey{public}
	list, sig := b.checksums(t, "1.8.3"), b.path("checksums.txt.sig")

	if err := b.run([]string{"sign", "-in", list, "-out", sig}); err != nil {
		t.Fatal(err)
	}
	b.out.Reset()
	if err := b.run([]string{"verify", "-in", list, "-sig", sig}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.out.String(), "gateon 1.8.3") {
		t.Errorf("verify said %q", b.out.String())
	}

	// One changed byte of the list and the same signature no longer holds.
	if err := os.WriteFile(list, []byte(strings.Replace(readFile(t, list), "1.8.3", "1.8.4", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := b.run([]string{"verify", "-in", list, "-sig", sig}); err == nil {
		t.Error("a signature verified over a list it was not made for")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestKeygenWritesAPrivateFileItWillNotOverwrite: the file may be the only
// copy of the key every installed gateway trusts.
func TestKeygenWritesAPrivateFileItWillNotOverwrite(t *testing.T) {
	b := newBench(t)
	private, _ := b.keygen(t)
	info, err := os.Stat(b.path("release.key"))
	if err != nil || info.Mode().Perm() != keyFileMode {
		t.Fatalf("key file mode %v, want %o (%v)", info.Mode().Perm(), keyFileMode, err)
	}
	if err := b.run([]string{"keygen", "-out", b.path("release.key")}); err == nil {
		t.Fatal("keygen overwrote an existing key file")
	}
	if readFile(t, b.path("release.key")) != private {
		t.Error("the refused keygen still changed the key file")
	}
	if strings.Contains(b.out.String()+b.errs.String(), strings.TrimSpace(private)) {
		t.Error("keygen printed the private key")
	}
}

// TestSignRefusesWhatNoGatewayWouldAccept: each of these would publish a
// release every gateway then refuses.
func TestSignRefusesWhatNoGatewayWouldAccept(t *testing.T) {
	b := newBench(t)
	private, public := b.keygen(t)
	sig := b.path("checksums.txt.sig")
	other, _, _ := ed25519.GenerateKey(nil)

	cases := []struct {
		name    string
		key     string
		trusted []ed25519.PublicKey
		version string
		want    string
	}{
		{"no key", "", []ed25519.PublicKey{public}, "1.8.3", "is not set"},
		{"not a key", "c2VjcmV0", []ed25519.PublicKey{public}, "1.8.3", "not a key written by"},
		{"a key the tree does not list", private, []ed25519.PublicKey{other}, "1.8.3", "release_keys.txt"},
		{"no key committed at all", private, nil, "1.8.3", "release_keys.txt"},
		{"a list gateways cannot read", private, []ed25519.PublicKey{public}, "1.8.3-next", "would refuse"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b.env[envKey], b.trusted = tc.key, tc.trusted
			err := b.run([]string{"sign", "-in", b.checksums(t, tc.version), "-out", sig})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one naming %q", err, tc.want)
			}
			if tc.key != "" && strings.Contains(err.Error(), strings.TrimSpace(tc.key)) {
				t.Error("the error repeats the key")
			}
			if _, statErr := os.Stat(sig); statErr == nil {
				t.Error("a refused sign still wrote a signature")
			}
		})
	}
}

// TestTheDryRunSignsWithAKeyNothingTrusts: the dry run holds no secret, and
// what it signs must not be mistakable for a release.
func TestTheDryRunSignsWithAKeyNothingTrusts(t *testing.T) {
	b := newBench(t)
	_, public := b.keygen(t)
	b.trusted = []ed25519.PublicKey{public}
	b.env[envEphemeral] = "1"
	list, sig := b.checksums(t, "1.8.3-next"), b.path("checksums.txt.sig")

	if err := b.run([]string{"sign", "-in", list, "-out", sig}); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(readFile(t, sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		t.Fatalf("the dry run's signature is not one: %v", err)
	}
	if err := b.run([]string{"verify", "-in", list, "-sig", sig}); err == nil {
		t.Error("a throwaway key's signature verified under the trusted keys")
	}
	if !strings.Contains(b.errs.String(), "throwaway") {
		t.Error("the dry run did not say its signature is worthless")
	}
}

// TestARealKeyWinsOverTheDryRunSwitch: a release must never go out under a
// throwaway key because an environment variable was left set.
func TestARealKeyWinsOverTheDryRunSwitch(t *testing.T) {
	b := newBench(t)
	private, public := b.keygen(t)
	b.env[envKey], b.env[envEphemeral] = private, "1"
	b.trusted = []ed25519.PublicKey{public}
	list, sig := b.checksums(t, "1.8.3"), b.path("checksums.txt.sig")
	if err := b.run([]string{"sign", "-in", list, "-out", sig}); err != nil {
		t.Fatal(err)
	}
	if err := b.run([]string{"verify", "-in", list, "-sig", sig}); err != nil {
		t.Errorf("signed with the throwaway key although a real one was given: %v", err)
	}
}

func TestKeysPrintsOneLinePerCommittedKey(t *testing.T) {
	b := newBench(t)
	if err := b.run([]string{"keys"}); err != nil || b.out.Len() != 0 {
		t.Fatalf("with no key: %q, %v", b.out.String(), err)
	}
	_, public := b.keygen(t)
	b.trusted = []ed25519.PublicKey{public, public}
	b.out.Reset()
	if err := b.run([]string{"keys"}); err != nil || strings.Count(b.out.String(), "\n") != 2 {
		t.Fatalf("with two keys: %q, %v", b.out.String(), err)
	}
}

func TestUnknownCommandsAreUsageErrors(t *testing.T) {
	b := newBench(t)
	for _, args := range [][]string{nil, {"publish"}, {"sign"}, {"verify", "-in", "x"}, {"keygen"}} {
		if err := b.run(args); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
}
