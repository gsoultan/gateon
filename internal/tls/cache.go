// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tls

import (
	"context"
	"errors"

	"github.com/gsoultan/gateon/internal/redis"
	"golang.org/x/crypto/acme/autocert"
)

// RedisCache implements autocert.Cache using Redis.
type RedisCache struct {
	client redis.Client
	prefix string
}

// NewRedisCache creates a new RedisCache.
func NewRedisCache(client redis.Client, prefix string) *RedisCache {
	if prefix == "" {
		prefix = "acme:"
	}
	return &RedisCache{client: client, prefix: prefix}
}

// Get reads a certificate data from Redis.
func (c *RedisCache) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := c.client.Get(ctx, c.prefix+key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, err
	}
	return val, nil
}

// Put writes a certificate data to Redis.
func (c *RedisCache) Put(ctx context.Context, key string, data []byte) error {
	return c.client.Set(ctx, c.prefix+key, data, 0).Err()
}

// Delete removes a certificate data from Redis.
func (c *RedisCache) Delete(ctx context.Context, key string) error {
	return c.client.Del(ctx, c.prefix+key).Err()
}
