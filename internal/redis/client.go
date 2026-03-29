package redis

import (
	"context"

	redigo "github.com/redis/go-redis/v9"
)

// Client defines the Redis operations used by Gateon.
type Client interface {
	redigo.Cmdable
	Subscribe(ctx context.Context, channels ...string) *redigo.PubSub
}

var Nil = redigo.Nil
