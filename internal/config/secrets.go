// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/hashicorp/vault/api"
)

const encPrefix = "enc:"

var (
	ErrEncryptionKeyMissing = errors.New("GATEON_ENCRYPTION_KEY not set")
	ErrDecryptFailed        = errors.New("decryption failed")
)

// SecretResolver is an interface that can resolve secrets at runtime.
type SecretResolver interface {
	Resolve(s string) (string, error)
}

// EnvSecretResolver resolves secrets from environment variables.
type EnvSecretResolver struct{}

func (r *EnvSecretResolver) Resolve(s string) (string, error) {
	name, ok := strings.CutPrefix(s, "$env:")
	if !ok {
		return s, nil
	}
	// An unset or misspelled variable used to resolve to "" with a nil error,
	// and the chain accepts any resolution that differs from the input -- so
	// "$env:GATEON_DB_URL" for a variable nobody exported became the empty
	// string, silently. decryptSensitiveFields runs this over
	// Auth.DatabaseUrl and Auth.PasetoSecret, and an empty database URL sends
	// db.AuthDatabaseURL to its "gateon.db" fallback: a Postgres-backed
	// install comes up on a local SQLite file, with a Paseto secret bootstrap
	// regenerates on every restart.
	//
	// LookupEnv distinguishes unset from empty. A deliberately empty variable
	// is still honoured; an absent one is an error the caller can see.
	value, present := os.LookupEnv(name)
	if !present {
		return s, fmt.Errorf("secret reference %q names an environment variable that is not set", s)
	}
	return value, nil
}

// VaultSecretResolver resolves secrets from HashiCorp Vault.
type VaultSecretResolver struct {
	client *api.Client
}

func NewVaultSecretResolver() (*VaultSecretResolver, error) {
	config := api.DefaultConfig()
	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}
	return &VaultSecretResolver{client: client}, nil
}

func (r *VaultSecretResolver) Resolve(s string) (string, error) {
	if !strings.HasPrefix(s, "$vault:") {
		return s, nil
	}
	path := s[7:]
	// Expected format: secret/data/mysecret#key
	parts := strings.SplitN(path, "#", 2)
	secretPath := parts[0]
	key := "data"
	if len(parts) > 1 {
		key = parts[1]
	}

	secret, err := r.client.Logical().Read(secretPath)
	if err != nil {
		return "", err
	}
	if secret == nil || secret.Data == nil {
		return "", errors.New("secret not found")
	}

	// Vault KV v2 wraps data in a "data" field
	data, ok := secret.Data["data"].(map[string]any)
	if ok {
		if val, ok := data[key].(string); ok {
			return val, nil
		}
	}

	// Try direct access for KV v1 or specific fields
	if val, ok := secret.Data[key].(string); ok {
		return val, nil
	}

	return "", fmt.Errorf("key %s not found in secret %s", key, secretPath)
}

// AWSSecretResolver resolves secrets from AWS Secrets Manager.
type AWSSecretResolver struct {
	client *secretsmanager.Client
}

func NewAWSSecretResolver() (*AWSSecretResolver, error) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}
	return &AWSSecretResolver{client: secretsmanager.NewFromConfig(cfg)}, nil
}

func (r *AWSSecretResolver) Resolve(s string) (string, error) {
	if !strings.HasPrefix(s, "$aws-sm:") {
		return s, nil
	}
	secretID := s[8:]
	// Format: secret-name#key
	parts := strings.SplitN(secretID, "#", 2)
	name := parts[0]
	key := ""
	if len(parts) > 1 {
		key = parts[1]
	}

	result, err := r.client.GetSecretValue(context.Background(), &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(name),
	})
	if err != nil {
		return "", err
	}

	if result.SecretString == nil {
		return "", errors.New("secret value is not a string")
	}

	if key == "" {
		return *result.SecretString, nil
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(*result.SecretString), &data); err != nil {
		return "", fmt.Errorf("failed to unmarshal secret JSON: %w", err)
	}

	if val, ok := data[key].(string); ok {
		return val, nil
	}

	return "", fmt.Errorf("key %s not found in AWS secret %s", key, name)
}

// secretReferencePrefixes are the value prefixes that name a secret held
// elsewhere rather than being the secret.
var secretReferencePrefixes = []string{"$env:", "$vault:", "$aws-sm:"}

// IsSecretReference reports whether s names a secret held elsewhere.
func IsSecretReference(s string) bool {
	for _, p := range secretReferencePrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// ChainSecretResolver resolves secret references by trying multiple resolvers.
type ChainSecretResolver struct {
	resolvers []SecretResolver
	// unavailable records why a resolver could not be built, so a reference
	// that needed it fails with the reason rather than with "not found".
	unavailable []error
}

// Resolve returns s unchanged when it is not a secret reference, and the
// secret it names when it is. A reference no resolver can answer is an error.
//
// It used to hand back the reference itself, with a nil error: with Vault
// unreachable, "$vault:secret/data/api#jwt" became the JWT signing secret, so a
// token HMAC-signed with that literal string was accepted, and an unresolved
// database_url opened a SQLite file named after the reference. A secret that
// cannot be read must stop what depends on it, not be replaced by its name.
func (r *ChainSecretResolver) Resolve(s string) (string, error) {
	if !IsSecretReference(s) {
		return s, nil
	}
	errs := append([]error(nil), r.unavailable...)
	for _, res := range r.resolvers {
		if res == nil {
			continue
		}
		resolved, err := res.Resolve(s)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if resolved != s {
			return resolved, nil
		}
	}
	if len(errs) == 0 {
		return "", fmt.Errorf("no secret resolver handles %q", referenceKind(s))
	}
	return "", fmt.Errorf("resolve %s reference: %w", referenceKind(s), errors.Join(errs...))
}

// referenceKind is the prefix of a reference, which is safe to log where the
// rest of it -- a path or variable name -- may not be.
func referenceKind(s string) string {
	for _, p := range secretReferencePrefixes {
		if strings.HasPrefix(s, p) {
			return p
		}
	}
	return "unknown"
}

// newDefaultResolver builds the chain from the resolvers this process can
// construct. A constructor that fails -- a malformed VAULT_SKIP_VERIFY, an
// unreadable AWS profile -- used to leave a nil in the chain, and the first
// reference to reach it was a nil-interface call at boot.
func newDefaultResolver() *ChainSecretResolver {
	chain := &ChainSecretResolver{resolvers: []SecretResolver{&EnvSecretResolver{}}}
	if v, err := NewVaultSecretResolver(); err == nil && v != nil {
		chain.resolvers = append(chain.resolvers, v)
	} else if err != nil {
		chain.unavailable = append(chain.unavailable, fmt.Errorf("vault resolver unavailable: %w", err))
	}
	if a, err := NewAWSSecretResolver(); err == nil && a != nil {
		chain.resolvers = append(chain.resolvers, a)
	} else if err != nil {
		chain.unavailable = append(chain.unavailable, fmt.Errorf("aws secrets manager resolver unavailable: %w", err))
	}
	return chain
}

// DefaultResolver is the default secret resolver.
var DefaultResolver SecretResolver = newDefaultResolver()

// ResolveSecretStrict decrypts s when it is encrypted and resolves it when it
// is a secret reference. It never returns an unusable value in place of the
// secret: ciphertext that cannot be decrypted and a reference that cannot be
// resolved are errors.
func ResolveSecretStrict(s string) (string, error) {
	plain, err := decryptStrict(s)
	if err != nil {
		return "", err
	}
	if !IsSecretReference(plain) {
		return plain, nil
	}
	if DefaultResolver == nil {
		return "", fmt.Errorf("no secret resolver is configured for %q", referenceKind(plain))
	}
	return DefaultResolver.Resolve(plain)
}

// GenerateRandomSecret generates a random hex string of the specified length in characters.
// For example, GenerateRandomSecret(32) returns a 32-character hex string.
func GenerateRandomSecret(length int) string {
	b := make([]byte, length/2)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// minEncryptionKeyLen is the shortest GATEON_ENCRYPTION_KEY that will be used.
// Documented in README.md and SECURITY.md as "min 16 chars".
const minEncryptionKeyLen = 16

// warnShortKeyOnce keeps the warning below to one line per process. This is
// called on every secret read and write, and a config reload walks all of them.
var warnShortKeyOnce sync.Once

// encryptionKey returns the 32-byte key derived from GATEON_ENCRYPTION_KEY.
// Returns nil if the env var is not set or too short.
//
// A key that is set but too short is warned about, loudly and once. Returning
// nil makes EncryptIfKeySet hand back its plaintext, so an operator who typed a
// short key gets the paseto secret, the database password and the database URL
// written to global.json in the clear, having done the one thing that was
// supposed to prevent it. The length rule is documented; a typo is not, and
// silence is indistinguishable from success here.
func encryptionKey() []byte {
	k := os.Getenv("GATEON_ENCRYPTION_KEY")
	if k == "" {
		return nil
	}
	if len(k) < minEncryptionKeyLen {
		warnShortKeyOnce.Do(func() {
			logger.L.LogWarn(
				"GATEON_ENCRYPTION_KEY is set but too short, so secrets are NOT being encrypted",
				"length", len(k), "minimum", minEncryptionKeyLen)
		})
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

// decryptStrict decrypts s when it carries the "enc:" prefix and returns
// anything else unchanged. Ciphertext it cannot decrypt -- no key, a short key,
// the wrong key -- is an error, where DecryptIfEncrypted hands the ciphertext
// back to be used as the secret.
func decryptStrict(s string) (string, error) {
	if !strings.HasPrefix(s, encPrefix) {
		return s, nil
	}
	key := encryptionKey()
	if key == nil {
		return "", fmt.Errorf("an encrypted secret needs GATEON_ENCRYPTION_KEY: %w", ErrEncryptionKeyMissing)
	}
	b, err := base64.RawStdEncoding.DecodeString(s[len(encPrefix):])
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrDecryptFailed, err)
	}
	dec, err := decrypt(b, key)
	if err != nil {
		return "", fmt.Errorf("%w (is GATEON_ENCRYPTION_KEY the key it was written with?): %w", ErrDecryptFailed, err)
	}
	return string(dec), nil
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
