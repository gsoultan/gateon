package auth

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func testEncKey() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

func TestEncryptDecryptSecret(t *testing.T) {
	key := testEncKey()
	tests := []struct {
		name      string
		plaintext string
	}{
		{"Empty", ""},
		{"Short", "JBSWY3DPEHPK3PXP"},
		{"Long", strings.Repeat("SECRET", 20)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := encryptSecret(key, tc.plaintext)
			if err != nil {
				t.Fatalf("encryptSecret: unexpected error: %v", err)
			}
			if tc.plaintext != "" {
				if !strings.HasPrefix(enc, encPrefix) {
					t.Fatalf("expected ciphertext to carry %q prefix, got %q", encPrefix, enc)
				}
				if strings.Contains(enc, tc.plaintext) {
					t.Fatalf("ciphertext leaks plaintext: %q", enc)
				}
			}
			dec, err := decryptSecret(key, enc)
			if err != nil {
				t.Fatalf("decryptSecret: unexpected error: %v", err)
			}
			if dec != tc.plaintext {
				t.Fatalf("round trip mismatch: got %q want %q", dec, tc.plaintext)
			}
		})
	}
}

func TestDecryptLegacyPlaintext(t *testing.T) {
	key := testEncKey()
	// Values stored before encryption was introduced have no prefix and must
	// be returned unchanged.
	got, err := decryptSecret(key, "PLAINTEXTSECRET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "PLAINTEXTSECRET" {
		t.Fatalf("legacy plaintext mismatch: got %q", got)
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key := testEncKey()
	enc, err := encryptSecret(key, "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("encryptSecret: %v", err)
	}
	// Flip the last character of the base64 payload.
	tampered := enc[:len(enc)-1]
	if enc[len(enc)-1] == 'A' {
		tampered += "B"
	} else {
		tampered += "A"
	}
	if _, err := decryptSecret(key, tampered); err == nil {
		t.Fatal("expected decryption of tampered ciphertext to fail")
	}
}

func TestGenerateRecoveryCodes(t *testing.T) {
	plain, hashed, err := generateRecoveryCodes()
	if err != nil {
		t.Fatalf("generateRecoveryCodes: %v", err)
	}
	if len(plain) != recoveryCodeCount || len(hashed) != recoveryCodeCount {
		t.Fatalf("expected %d codes, got plain=%d hashed=%d", recoveryCodeCount, len(plain), len(hashed))
	}

	seen := make(map[string]bool)
	for i, code := range plain {
		if len(code) < 12 {
			t.Errorf("recovery code %d too weak: %q", i, code)
		}
		if seen[code] {
			t.Errorf("duplicate recovery code generated: %q", code)
		}
		seen[code] = true
		if strings.Contains(hashed[i], ",") {
			t.Errorf("hash %d contains comma separator: %q", i, hashed[i])
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hashed[i]), []byte(code)); err != nil {
			t.Errorf("hash %d does not verify against its code: %v", i, err)
		}
	}
}

func TestMatchRecoveryCode(t *testing.T) {
	plain, hashed, err := generateRecoveryCodes()
	if err != nil {
		t.Fatalf("generateRecoveryCodes: %v", err)
	}

	tests := []struct {
		name string
		code string
		want int
	}{
		{"ExactMatch", plain[3], 3},
		{"Lowercase", strings.ToLower(plain[5]), 5},
		{"WithSpaces", " " + plain[0] + " ", 0},
		{"Empty", "", -1},
		{"Unknown", "ZZZZZZZZZZZZZZZZ", -1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchRecoveryCode(hashed, tc.code); got != tc.want {
				t.Errorf("matchRecoveryCode(%q) = %d; want %d", tc.code, got, tc.want)
			}
		})
	}
}

func TestRemoveAt(t *testing.T) {
	src := []string{"a", "b", "c", "d"}
	got := removeAt(src, 1)
	want := []string{"a", "c", "d"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("removeAt = %v; want %v", got, want)
	}
	// The source slice must remain unmodified (no in-place aliasing).
	if strings.Join(src, ",") != "a,b,c,d" {
		t.Fatalf("removeAt mutated the source slice: %v", src)
	}
}
