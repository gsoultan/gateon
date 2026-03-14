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
	return Cache(CacheConfig{
		TTLSeconds:  ttl,
		MaxEntries:  maxEntries,
		MaxBodyKB:   int64(maxBodyKB),
		Storage:     storage,
		RedisClient: f.redisClient,
	}), nil
}
