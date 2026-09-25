// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/redis"
)

func NewCache(cfg map[string]string, redisClient redis.Client) (kind.Middleware, error) {
	ttl, err := kind.ParseIntStrict(cfg["ttl_seconds"], 0)
	if err != nil {
		return nil, kind.CfgError("ttl_seconds", cfg["ttl_seconds"], err)
	}
	maxEntries, err := kind.ParseIntStrict(cfg["max_entries"], 0)
	if err != nil {
		return nil, kind.CfgError("max_entries", cfg["max_entries"], err)
	}
	maxBodyKB, err := kind.ParseIntStrict(cfg["max_body_kb"], 0)
	if err != nil {
		return nil, kind.CfgError("max_body_kb", cfg["max_body_kb"], err)
	}
	storage := cfg["storage"]
	if storage == "" {
		storage = CacheStorageMemory
	}
	// The route reaches the middleware through cfg[kind.RouteIDKey], set by
	// Factory.Create. Cache() hardcodes an empty route, which left every
	// factory-built cache reporting its hit/miss metrics under the empty label
	// and, on the shared Redis backend, keying entries with no route at all.
	return CacheWithRoute(CacheConfig{
		TTLSeconds:  ttl,
		MaxEntries:  maxEntries,
		MaxBodyKB:   int64(maxBodyKB),
		Storage:     storage,
		RedisClient: redisClient,
		RouteKey:    cfg[kind.RouteStateKey],
	}, cfg[kind.RouteIDKey]), nil
}
