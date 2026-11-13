// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package selfupdate

import (
	"bytes"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// signatureContext is signed in front of the release list, so a signature
// made here is never a valid signature over anything else the same key might
// one day sign.
const signatureContext = "gateon-release-checksums-v1\n"

// MaxSignatureBytes bounds a checksums.txt.sig: one base64 line.
const MaxSignatureBytes = 1 << 10

// ErrSignature is wrapped by every refusal of a release list on its
// signature.
var ErrSignature = errors.New("the release list is not signed by a gateon release key")

// releaseKeysFile is the release keys this binary trusts: one base64 Ed25519
// public key per line. More than one line is a rotation in progress. It is
// written by "go run ./scripts/releasesign keygen" and committed; the private
// half never enters the repository.
//
//go:embed release_keys.txt
var releaseKeysFile []byte

// ReleaseKeys are the keys compiled into this binary. None means the build
// cannot verify a release, and says so rather than trusting one.
var ReleaseKeys = sync.OnceValue(func() []ed25519.PublicKey {
	keys, err := ParseKeys(releaseKeysFile)
	if err != nil {
		// A test holds the committed file to ParseKeys, so this is a build
		// from a tree that test never saw. Trusting nothing is the safe half.
		return nil
	}
	return keys
})

// ParseKeys reads a release key file: a base64 Ed25519 public key per line,
// with blank lines and "#" comments ignored.
func ParseKeys(data []byte) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("release key %q is not a base64 Ed25519 public key", line)
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	return keys, nil
}

// Sign signs a release list. The result is the content of checksums.txt.sig.
func Sign(key ed25519.PrivateKey, checksums []byte) []byte {
	sig := ed25519.Sign(key, signedMessage(checksums))
	return []byte(base64.StdEncoding.EncodeToString(sig) + "\n")
}

// Verify reports whether sig is a signature over checksums by one of keys.
// With no keys nothing verifies.
func Verify(keys []ed25519.PublicKey, checksums, sig []byte) error {
	raw, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("%w: the signature file is not a base64 Ed25519 signature", ErrSignature)
	}
	msg := signedMessage(checksums)
	for _, k := range keys {
		if ed25519.Verify(k, msg, raw) {
			return nil
		}
	}
	return ErrSignature
}

func signedMessage(checksums []byte) []byte {
	msg := make([]byte, 0, len(signatureContext)+len(checksums))
	msg = append(msg, signatureContext...)
	return append(msg, checksums...)
}
