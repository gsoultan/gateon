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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
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
	if strings.HasPrefix(s, "$env:") {
		return os.Getenv(s[5:]), nil
	}
	return s, nil
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

// ChainSecretResolver resolves secrets by trying multiple resolvers.
type ChainSecretResolver struct {
	resolvers []SecretResolver
}

func (r *ChainSecretResolver) Resolve(s string) (string, error) {
	for _, res := range r.resolvers {
		resolved, err := res.Resolve(s)
		if err == nil && resolved != s {
			return resolved, nil
		}
	}
	return s, nil
}

// DefaultResolver is the default secret resolver.
var DefaultResolver SecretResolver = &ChainSecretResolver{
	resolvers: []SecretResolver{
		&EnvSecretResolver{},
		func() SecretResolver {
			v, _ := NewVaultSecretResolver()
			if v != nil {
				return v
			}
			return nil
		}(),
		func() SecretResolver {
			a, _ := NewAWSSecretResolver()
			if a != nil {
				return a
			}
			return nil
		}(),
	},
}

// ResolveSecret resolves s using DecryptIfEncrypted and the DefaultResolver.
func ResolveSecret(s string) string {
	s = DecryptIfEncrypted(s)
	if DefaultResolver != nil {
		if resolved, err := DefaultResolver.Resolve(s); err == nil {
			return resolved
		}
	}
	return s
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
