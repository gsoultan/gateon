// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

const (
	goodKey  = "a-sufficiently-long-encryption-key"
	otherKey = "a-different-but-also-long-enough-key"
)

// TestSecretRoundTrip is the property the whole file exists for: what goes in
// comes back, for the values this is actually applied to.
func TestSecretRoundTrip(t *testing.T) {
	t.Setenv("GATEON_ENCRYPTION_KEY", goodKey)

	for _, plain := range []string{
		"hunter2",
		"postgres://user:p%40ssw0rd@db.internal:5432/gateon?sslmode=require",
		strings.Repeat("x", 4096),
		"unicode: ✓ é 日本語",
		"has:colons:and enc: inside it",
	} {
		t.Run(plain[:min(len(plain), 24)], func(t *testing.T) {
			enc := EncryptIfKeySet(plain)
			if enc == plain {
				t.Fatal("the value came back unchanged; nothing was encrypted")
			}
			if !strings.HasPrefix(enc, encPrefix) {
				t.Errorf("ciphertext %q lacks the %q marker, so nothing will decrypt it", enc, encPrefix)
			}
			if strings.Contains(enc, plain) {
				t.Error("the plaintext is still visible inside the ciphertext")
			}
			if got := DecryptIfEncrypted(enc); got != plain {
				t.Errorf("round trip returned %q, want %q", got, plain)
			}
		})
	}
}

// TestEncryptionUsesAFreshNonce catches the worst thing that can go wrong with
// AES-GCM. Reusing a nonce under one key leaks the plaintext relationship and
// breaks the authentication guarantee outright.
func TestEncryptionUsesAFreshNonce(t *testing.T) {
	t.Setenv("GATEON_ENCRYPTION_KEY", goodKey)

	const plain = "the same secret every time"
	seen := make(map[string]bool)
	for range 32 {
		enc := EncryptIfKeySet(plain)
		if seen[enc] {
			t.Fatalf("encrypting %q twice produced the same ciphertext; the nonce is not fresh", plain)
		}
		seen[enc] = true
		if got := DecryptIfEncrypted(enc); got != plain {
			t.Fatalf("decrypt returned %q, want %q", got, plain)
		}
	}
}

// TestDecryptRejectsTamperedCiphertext checks the authentication half of GCM is
// actually load-bearing. Without it an attacker who can write global.json could
// flip bits in the stored paseto secret rather than having to read it.
func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	t.Setenv("GATEON_ENCRYPTION_KEY", goodKey)
	enc := EncryptIfKeySet("original-secret")

	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(enc, encPrefix))
	if err != nil {
		t.Fatalf("decoding our own ciphertext: %v", err)
	}

	tests := map[string]func([]byte) []byte{
		"a flipped bit in the ciphertext": func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[len(out)-1] ^= 0x01
			return out
		},
		"a flipped bit in the nonce": func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[0] ^= 0x01
			return out
		},
		"truncated": func(b []byte) []byte { return b[:len(b)-1] },
		"empty":     func([]byte) []byte { return nil },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			tampered := encPrefix + base64.RawStdEncoding.EncodeToString(mutate(raw))
			// A failed decrypt returns the input unchanged, so the caller sees
			// the "enc:" string rather than a forged plaintext.
			if got := DecryptIfEncrypted(tampered); got != tampered {
				t.Errorf("tampered value decrypted to %q; GCM authentication did not reject it", got)
			}
		})
	}
}

// TestDecryptWithTheWrongKeyFails is the other authentication case: a different
// key must not produce a plausible-looking value.
func TestDecryptWithTheWrongKeyFails(t *testing.T) {
	t.Setenv("GATEON_ENCRYPTION_KEY", goodKey)
	enc := EncryptIfKeySet("secret-under-the-first-key")

	t.Setenv("GATEON_ENCRYPTION_KEY", otherKey)
	if got := DecryptIfEncrypted(enc); got != enc {
		t.Errorf("decrypted to %q under a different key, want the input returned unchanged", got)
	}
}

// TestNoKeyMeansNoEncryption documents the opt-in default. Encryption is off
// unless the operator turns it on, and an unencrypted value must survive a
// decrypt attempt untouched.
func TestNoKeyMeansNoEncryption(t *testing.T) {
	t.Setenv("GATEON_ENCRYPTION_KEY", "")

	const plain = "plaintext-secret"
	if got := EncryptIfKeySet(plain); got != plain {
		t.Errorf("EncryptIfKeySet = %q with no key set, want the input", got)
	}
	if got := DecryptIfEncrypted(plain); got != plain {
		t.Errorf("DecryptIfEncrypted mangled a value that was never encrypted: %q", got)
	}
}

// TestAShortKeyDoesNotEncrypt pins the behaviour that motivated the warning.
// The value is stored in the clear, which is what the operator was trying to
// avoid, so the log line is the only thing standing between them and a paseto
// secret on disk.
func TestAShortKeyDoesNotEncrypt(t *testing.T) {
	for _, key := range []string{"x", "short", strings.Repeat("k", minEncryptionKeyLen-1)} {
		t.Run(key[:min(len(key), 10)], func(t *testing.T) {
			t.Setenv("GATEON_ENCRYPTION_KEY", key)
			if encryptionKey() != nil {
				t.Errorf("a %d-character key was accepted; the minimum is %d",
					len(key), minEncryptionKeyLen)
			}
			const plain = "should-have-been-encrypted"
			if got := EncryptIfKeySet(plain); got != plain {
				t.Errorf("EncryptIfKeySet = %q, want the plaintext back", got)
			}
		})
	}

	t.Run("exactly at the minimum is accepted", func(t *testing.T) {
		t.Setenv("GATEON_ENCRYPTION_KEY", strings.Repeat("k", minEncryptionKeyLen))
		if encryptionKey() == nil {
			t.Errorf("a key of exactly %d characters was rejected", minEncryptionKeyLen)
		}
	})
}

// TestEmptyStringIsNotEncrypted keeps an unset optional secret from turning into
// a ciphertext that looks configured.
func TestEmptyStringIsNotEncrypted(t *testing.T) {
	t.Setenv("GATEON_ENCRYPTION_KEY", goodKey)
	if got := EncryptIfKeySet(""); got != "" {
		t.Errorf("EncryptIfKeySet(\"\") = %q, want empty", got)
	}
}

func TestDecodeHexKey(t *testing.T) {
	valid := strings.Repeat("ab", 32) // 64 hex chars
	key, err := DecodeHexKey(valid)
	if err != nil {
		t.Fatalf("DecodeHexKey on a valid key: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("decoded %d bytes, want 32 for AES-256", len(key))
	}

	for name, in := range map[string]string{
		"too short":             strings.Repeat("ab", 31),
		"too long":              strings.Repeat("ab", 33),
		"empty":                 "",
		"right length, not hex": strings.Repeat("zz", 32),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeHexKey(in); err == nil {
				t.Errorf("DecodeHexKey(%q...) accepted an invalid key", in[:min(len(in), 8)])
			}
		})
	}
}

func TestGenerateRandomSecret(t *testing.T) {
	seen := make(map[string]bool)
	for range 16 {
		s := GenerateRandomSecret(32)
		if len(s) != 32 {
			t.Fatalf("length = %d, want 32", len(s))
		}
		if seen[s] {
			t.Fatal("GenerateRandomSecret repeated a value")
		}
		seen[s] = true
	}
}
