package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// encPrefix marks a value as AES-GCM encrypted so legacy plaintext values
// (stored before encryption was introduced) can still be read transparently.
const encPrefix = "enc:"

// recoveryCodeBytes is the number of random bytes per recovery code (80 bits of entropy).
const recoveryCodeBytes = 10

// recoveryCodeCount is the number of recovery codes generated during 2FA setup.
const recoveryCodeCount = 10

// recoveryCodeEncoding produces uppercase, padding-free, human-friendly codes.
var recoveryCodeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// encryptSecret encrypts the TOTP secret at rest using AES-256-GCM with the
// provided 32-byte key. The result is marked with encPrefix and base64 encoded.
func encryptSecret(key []byte, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to read nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptSecret reverses encryptSecret. Values without encPrefix are returned
// as-is to remain backward compatible with previously stored plaintext secrets.
func decryptSecret(key []byte, stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	enc, ok := strings.CutPrefix(stored, encPrefix)
	if !ok {
		// Legacy plaintext secret.
		return stored, nil
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", fmt.Errorf("failed to decode secret: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create gcm: %w", err)
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt secret: %w", err)
	}
	return string(plaintext), nil
}

// generateRecoveryCodes returns a set of cryptographically random recovery codes
// in plaintext (to display once to the user) alongside their bcrypt hashes (for
// storage at rest).
func generateRecoveryCodes() (plain []string, hashed []string, err error) {
	plain = make([]string, recoveryCodeCount)
	hashed = make([]string, recoveryCodeCount)
	for i := range recoveryCodeCount {
		buf := make([]byte, recoveryCodeBytes)
		if _, err = rand.Read(buf); err != nil {
			return nil, nil, fmt.Errorf("failed to generate recovery code: %w", err)
		}
		code := recoveryCodeEncoding.EncodeToString(buf)
		plain[i] = code
		hash, hErr := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if hErr != nil {
			return nil, nil, fmt.Errorf("failed to hash recovery code: %w", hErr)
		}
		hashed[i] = string(hash)
	}
	return plain, hashed, nil
}

// normalizeRecoveryCode strips formatting and uppercases a user-supplied code so
// it matches the encoding produced by generateRecoveryCodes.
func normalizeRecoveryCode(code string) string {
	replacer := strings.NewReplacer(" ", "", "-", "")
	return strings.ToUpper(replacer.Replace(strings.TrimSpace(code)))
}

// matchRecoveryCode returns the index of the hashed recovery code that matches
// the supplied plaintext code, or -1 if none match. bcrypt comparison is
// constant-time with respect to the hash, avoiding timing side-channels.
func matchRecoveryCode(hashes []string, code string) int {
	normalized := normalizeRecoveryCode(code)
	if normalized == "" {
		return -1
	}
	for i, h := range hashes {
		if h == "" {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(normalized)) == nil {
			return i
		}
	}
	return -1
}

// removeAt returns a new slice with the element at index i removed, without
// mutating the backing array of the input slice.
func removeAt(s []string, i int) []string {
	out := make([]string, 0, len(s)-1)
	out = append(out, s[:i]...)
	out = append(out, s[i+1:]...)
	return out
}
