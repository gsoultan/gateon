package redis

import redigo "github.com/redis/go-redis/v9"

// Client defines the Redis operations used by Gateon.
// *redis.Client implements this interface for DI and testability.
type Client interface {
	redigo.Cmdable
}
