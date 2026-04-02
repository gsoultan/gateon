package redis

import (
	"context"
	"strings"

	redigo "github.com/redis/go-redis/v9"
)

// Client defines the Redis operations used by Gateon.
type Client interface {
	redigo.Cmdable
	Subscribe(ctx context.Context, channels ...string) *redigo.PubSub
	Close() error
}

var Nil = redigo.Nil

// NewClient returns a standard or cluster Redis client based on the provided addresses.
func NewClient(addr string) Client {
	addrs := strings.Split(addr, ",")
	if len(addrs) > 1 {
		return redigo.NewClusterClient(&redigo.ClusterOptions{
			Addrs: addrs,
		})
	}
	return redigo.NewClient(&redigo.Options{
		Addr: addr,
	})
}
