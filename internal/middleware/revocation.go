package middleware

import (
	"context"
	"fmt"
	"time"

	"github.com/gsoultan/gateon/internal/redis"
)

// RevocationStore defines the interface for checking if a token (jti) is revoked.
type RevocationStore interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
	Revoke(ctx context.Context, jti string, expiration time.Duration) error
}

// RedisRevocationStore implements RevocationStore using Redis.
type RedisRevocationStore struct {
	client redis.Client
	prefix string
}

// NewRedisRevocationStore creates a new RedisRevocationStore.
func NewRedisRevocationStore(client redis.Client, prefix string) *RedisRevocationStore {
	if prefix == "" {
		prefix = "revoked_jti:"
	}
	return &RedisRevocationStore{
		client: client,
		prefix: prefix,
	}
}

func (s *RedisRevocationStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	if jti == "" {
		return false, nil
	}
	val, err := s.client.Exists(ctx, s.prefix+jti).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check revocation in redis: %w", err)
	}
	return val > 0, nil
}

func (s *RedisRevocationStore) Revoke(ctx context.Context, jti string, expiration time.Duration) error {
	if jti == "" {
		return nil
	}
	err := s.client.Set(ctx, s.prefix+jti, "1", expiration).Err()
	if err != nil {
		return fmt.Errorf("failed to revoke jti in redis: %w", err)
	}
	return nil
}
