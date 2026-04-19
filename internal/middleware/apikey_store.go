package middleware

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/gsoultan/gateon/internal/redis"
)

// APIKeyStore defines the interface for retrieving tenant ID from an API key.
type APIKeyStore interface {
	GetTenantID(ctx context.Context, key string) (string, bool, error)
}

// MemoryAPIKeyStore implements APIKeyStore using a map.
type MemoryAPIKeyStore struct {
	keys   map[string]string
	hashed bool
}

// NewMemoryAPIKeyStore creates a new MemoryAPIKeyStore.
func NewMemoryAPIKeyStore(keys map[string]string, hashed bool) *MemoryAPIKeyStore {
	return &MemoryAPIKeyStore{
		keys:   keys,
		hashed: hashed,
	}
}

func (s *MemoryAPIKeyStore) GetTenantID(ctx context.Context, key string) (string, bool, error) {
	searchKey := key
	if s.hashed {
		hash := sha256.Sum256([]byte(key))
		searchKey = hex.EncodeToString(hash[:])
	}

	// If hashed, we use constant-time comparison if we were iterating,
	// but with a map lookup it's different.
	// However, for hashed keys, we can just look up the hash.
	tenantID, ok := s.keys[searchKey]
	return tenantID, ok, nil
}

// RedisAPIKeyStore implements APIKeyStore using Redis.
type RedisAPIKeyStore struct {
	client redis.Client
	prefix string
	hashed bool
}

// NewRedisAPIKeyStore creates a new RedisAPIKeyStore.
func NewRedisAPIKeyStore(client redis.Client, prefix string, hashed bool) *RedisAPIKeyStore {
	if prefix == "" {
		prefix = "apikey:"
	}
	return &RedisAPIKeyStore{
		client: client,
		prefix: prefix,
		hashed: hashed,
	}
}

func (s *RedisAPIKeyStore) GetTenantID(ctx context.Context, key string) (string, bool, error) {
	searchKey := key
	if s.hashed {
		hash := sha256.Sum256([]byte(key))
		searchKey = hex.EncodeToString(hash[:])
	}

	val, err := s.client.Get(ctx, s.prefix+searchKey).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("failed to get api key from redis: %w", err)
	}

	return val, true, nil
}

// ConstantTimeCompare compares two strings in constant time.
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
