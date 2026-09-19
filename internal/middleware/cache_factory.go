// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"strconv"
)

func (f *Factory) createCache(cfg map[string]string) (Middleware, error) {
	ttl, _ := strconv.Atoi(cfg["ttl_seconds"])
	maxEntries, _ := strconv.Atoi(cfg["max_entries"])
	maxBodyKB, _ := strconv.Atoi(cfg["max_body_kb"])
	storage := cfg["storage"]
	if storage == "" {
		storage = CacheStorageMemory
	}
	// The route reaches the middleware through cfg["route_id"], set by
	// Factory.Create. Cache() hardcodes an empty route, which left every
	// factory-built cache reporting its hit/miss metrics under the empty label
	// and, on the shared Redis backend, keying entries with no route at all.
	return CacheWithRoute(CacheConfig{
		TTLSeconds:  ttl,
		MaxEntries:  maxEntries,
		MaxBodyKB:   int64(maxBodyKB),
		Storage:     storage,
		RedisClient: f.redisClient,
	}, cfg["route_id"]), nil
}
