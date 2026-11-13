// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Command releasesign makes and uses the key gateon releases are signed with
// (ADR 0085). A gateway believes a release list only when its checksums.txt.sig
// verifies under a key compiled into that gateway, so the release build and
// the gateway have to agree on the format; both use internal/selfupdate, and
// this command is the build's half.
//
// Usage:
//
//	go run ./scripts/releasesign keygen -out <private key file>
//	go run ./scripts/releasesign sign -in checksums.txt -out checksums.txt.sig
//	go run ./scripts/releasesign verify -in checksums.txt -sig checksums.txt.sig
//	go run ./scripts/releasesign keys
//
// keygen writes the private key to a new file, mode 0600, and prints the
// public line to add to internal/selfupdate/release_keys.txt. The private key
// never belongs in the repository: it goes into the GATEON_RELEASE_SIGNING_KEY
// secret, which is where sign reads it from.
//
// sign refuses to produce a signature no gateway would accept: the key must be
// one release_keys.txt already lists, and the list must be one a gateway can
// read. A release that fails either would publish, and then every gateway
// would refuse it, which nobody would notice until an upgrade was wanted.
//
// With GATEON_RELEASE_SIGN_EPHEMERAL=1 and no key, sign uses a key it throws
// away. That is for the release workflow's dry run, which holds no secrets and
// publishes nothing, so that the signing step is still run and its output
// still checked on every dry run.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gsoultan/gateon/internal/selfupdate"
)

const (
	envKey       = "GATEON_RELEASE_SIGNING_KEY"
	envEphemeral = "GATEON_RELEASE_SIGN_EPHEMERAL"

	keyFileMode = 0o600
	sigFileMode = 0o644
)

var errUsage = errors.New("usage: releasesign keygen -out <file> | sign -in <checksums> -out <sig> | verify -in <checksums> -sig <sig> | keys")

// tool is the command with everything it reads from the process made a field,
// so the tests run it without a process.
type tool struct {
	getenv func(string) string
	keys   func() []ed25519.PublicKey
	stdout io.Writer
	stderr io.Writer
}

func main() {
	t := tool{getenv: os.Getenv, keys: selfupdate.ReleaseKeys, stdout: os.Stdout, stderr: os.Stderr}
	if err := t.run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "releasesign:", err)
		os.Exit(1)
	}
}

func (t tool) run(args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(t.stderr)
	in := fs.String("in", "", "the checksums.txt to sign or verify")
	out := fs.String("out", "", "the file to write")
	sig := fs.String("sig", "", "the checksums.txt.sig to verify")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "keygen":
		return t.keygen(*out)
	case "sign":
		return t.sign(*in, *out)
	case "verify":
		return t.verify(*in, *sig)
	case "keys":
		return t.listKeys()
	default:
		return errUsage
	}
}

// keygen never overwrites: the file it would replace may be the only copy of
// the key every installed gateway trusts.
func (t tool) keygen(out string) error {
	if out == "" {
		return errUsage
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// #nosec G304 G703 -- a release-build command; the path is the one its operator named on the command line.
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, keyFileMode)
	if err != nil {
		return fmt.Errorf("the private key was not written: %w", err)
	}
	if _, err := fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(t.stderr, "Private key written to %s. Store its content as the %s secret and keep the file out of the repository.\n", out, envKey)
	fmt.Fprintln(t.stderr, "Add this line to internal/selfupdate/release_keys.txt:")
	fmt.Fprintln(t.stdout, base64.StdEncoding.EncodeToString(pub))
	return nil
}

func (t tool) sign(in, out string) error {
	if in == "" || out == "" {
		return errUsage
	}
	// #nosec G304 G703 -- a release-build command; the path is the one its operator named on the command line.
	checksums, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	key, err := t.signingKey(checksums)
	if err != nil {
		return err
	}
	// #nosec G306 G703 -- the signature is published; a release-build command; the path is the one its operator named on the command line.
	return os.WriteFile(out, selfupdate.Sign(key, checksums), sigFileMode)
}

// signingKey is the key to sign checksums with, after everything that would
// make the signature useless to a gateway has been ruled out.
func (t tool) signingKey(checksums []byte) (ed25519.PrivateKey, error) {
	encoded := strings.TrimSpace(t.getenv(envKey))
	if encoded == "" && t.getenv(envEphemeral) == "1" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		fmt.Fprintln(t.stderr, "releasesign: signing with a throwaway key; no gateway will accept this signature")
		return priv, err
	}
	if encoded == "" {
		return nil, fmt.Errorf("%s is not set", envKey)
	}
	seed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(seed) != ed25519.SeedSize {
		// The value is never echoed: it is the key.
		return nil, fmt.Errorf("%s is not a key written by releasesign keygen", envKey)
	}
	key := ed25519.NewKeyFromSeed(seed)
	if !t.trusts(key) {
		return nil, fmt.Errorf("%s is not a key internal/selfupdate/release_keys.txt lists, so no gateway built from this tree would accept its signature", envKey)
	}
	if _, err := selfupdate.ParseChecksums(checksums); err != nil {
		return nil, fmt.Errorf("gateways would refuse this release: %w", err)
	}
	return key, nil
}

func (t tool) trusts(key ed25519.PrivateKey) bool {
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return false
	}
	for _, k := range t.keys() {
		if k.Equal(pub) {
			return true
		}
	}
	return false
}

// verify checks a signature the way a gateway built from this tree would.
func (t tool) verify(in, sig string) error {
	if in == "" || sig == "" {
		return errUsage
	}
	// #nosec G304 G703 -- a release-build command; the path is the one its operator named on the command line.
	checksums, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	// #nosec G304 G703 -- as above.
	signature, err := os.ReadFile(sig)
	if err != nil {
		return err
	}
	if err := selfupdate.Verify(t.keys(), checksums, signature); err != nil {
		return err
	}
	rel, err := selfupdate.ParseChecksums(checksums)
	if err != nil {
		return err
	}
	fmt.Fprintf(t.stdout, "verified: gateon %s, %d files\n", rel.Version, len(rel.Artifacts))
	return nil
}

// listKeys prints the committed public keys, one a line. The release workflow
// counts the lines to decide whether a release must be signed.
func (t tool) listKeys() error {
	for _, k := range t.keys() {
		fmt.Fprintln(t.stdout, base64.StdEncoding.EncodeToString(k))
	}
	return nil
}
