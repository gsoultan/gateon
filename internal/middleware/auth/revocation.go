// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/redis"
)

// RevocationStore defines the interface for checking if a token (jti) is revoked.
type RevocationStore interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
	Revoke(ctx context.Context, jti string, expiration time.Duration) error
}

// ErrRevocationNeedsRedis refuses "Enable Revocation" on a gateway with no
// Redis (ADR 0046). The revocation list is the Redis keys "<prefix><jti>" an
// operator writes; without Redis there is nowhere to write one, and the gateway
// has no other way to be told a token is revoked, so the switch would check an
// empty list on every request.
var ErrRevocationNeedsRedis = errors.New("revocation needs Redis: the revocation list is the Redis keys " +
	"<revocation_prefix><jti> (default prefix \"revoked_jti:\"), and this gateway has no Redis configured; " +
	"configure Redis in Settings and restart, or turn Enable Revocation off")

// checkRevocation refuses a verified token whose ID (jti) the store lists as
// revoked. A token without a jti cannot be named in the list and is not
// refused by it.
//
// A failed lookup refuses the request rather than being read as "not revoked".
// RedisRevocationStore returns (false, err) when the backend is unreachable,
// so treating a failed lookup as "not revoked" honoured every revoked token
// for as long as Redis was down -- a restart, a network blip, a timeout or a
// wrong password. Revocation is the control you reach for after a compromise,
// which makes an outage precisely the wrong moment to stop enforcing it, and
// the operator turned this on deliberately.
//
// The cause goes to the log, not to the caller: HandleFailure writes
// err.Error() straight into the response body, so a wrapped driver error
// would hand an unauthenticated client the address of an internal service.
func checkRevocation(ctx context.Context, store RevocationStore, claims map[string]any) error {
	if store == nil {
		return nil
	}
	jti, _ := claims["jti"].(string)
	revoked, err := store.IsRevoked(ctx, jti)
	if err != nil {
		logger.L.LogError("auth: revocation lookup failed, denying request", "error", err)
		return errors.New("token revocation status unavailable")
	}
	if revoked {
		return errors.New("token revoked")
	}
	return nil
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
