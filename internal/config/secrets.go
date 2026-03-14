package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

const encPrefix = "enc:"

var (
	ErrEncryptionKeyMissing = errors.New("GATEON_ENCRYPTION_KEY not set")
	ErrDecryptFailed        = errors.New("decryption failed")
)

// encryptionKey returns the 32-byte key derived from GATEON_ENCRYPTION_KEY.
// Returns nil if the env var is not set or too short.
func encryptionKey() []byte {
	k := os.Getenv("GATEON_ENCRYPTION_KEY")
	if k == "" || len(k) < 16 {
		return nil
	}
	h := sha256.Sum256([]byte(k))
	return h[:]
}

// EncryptIfKeySet encrypts s with AES-256-GCM if GATEON_ENCRYPTION_KEY is set.
// Returns "enc:base64(nonce+tag+ciphertext)" or the original string.
func EncryptIfKeySet(s string) string {
	key := encryptionKey()
	if key == nil || s == "" {
		return s
	}
	out, err := encrypt([]byte(s), key)
	if err != nil {
		return s
	}
	return encPrefix + base64.RawStdEncoding.EncodeToString(out)
}

// DecryptIfEncrypted decrypts s if it has the "enc:" prefix.
// Returns the decrypted string or the original if not encrypted.
func DecryptIfEncrypted(s string) string {
	if s == "" || len(s) < len(encPrefix) || s[:len(encPrefix)] != encPrefix {
		return s
	}
	key := encryptionKey()
	if key == nil {
		return s
	}
	b, err := base64.RawStdEncoding.DecodeString(s[len(encPrefix):])
	if err != nil {
		return s
	}
	dec, err := decrypt(b, key)
	if err != nil {
		return s
	}
	return string(dec)
}

func encrypt(plain, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrDecryptFailed
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// DecodeHexKey decodes a 64-char hex string into 32 bytes (for AES-256).
func DecodeHexKey(hexKey string) ([]byte, error) {
	if len(hexKey) != 64 {
		return nil, errors.New("key must be 64 hex characters")
	}
	return hex.DecodeString(hexKey)
}
