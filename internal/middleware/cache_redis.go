package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gsoultan/gateon/internal/redis"
	redigo "github.com/redis/go-redis/v9"
)

const cacheKeyPrefix = "gateon:cache:"

type redisCacheBackend struct {
	client redis.Client
}

// NewRedisCacheBackend creates a Redis-backed cache store for distributed response caching.
func NewRedisCacheBackend(client redis.Client) CacheBackend {
	if client == nil {
		return nil
	}
	return &redisCacheBackend{client: client}
}

type cachedPayload struct {
	Status  int                 `json:"s"`
	Headers map[string][]string `json:"h"`
	BodyB64 string              `json:"b"`
}

func (r *redisCacheBackend) Get(ctx context.Context, key string) (status int, headers http.Header, body []byte, ok bool) {
	fullKey := cacheKeyPrefix + key
	val, err := r.client.Get(ctx, fullKey).Bytes()
	if err == redigo.Nil {
		return 0, nil, nil, false
	}
	if err != nil {
		return 0, nil, nil, false
	}
	var p cachedPayload
	if err := json.Unmarshal(val, &p); err != nil {
		return 0, nil, nil, false
	}
	body, err = base64.StdEncoding.DecodeString(p.BodyB64)
	if err != nil {
		return 0, nil, nil, false
	}
	headers = make(http.Header)
	for k, vv := range p.Headers {
		for _, v := range vv {
			headers.Add(k, v)
		}
	}
	return p.Status, headers, body, true
}

func (r *redisCacheBackend) Set(ctx context.Context, key string, status int, headers http.Header, body []byte, ttl time.Duration) {
	fullKey := cacheKeyPrefix + key
	h := make(map[string][]string)
	for k, vv := range headers {
		h[k] = append([]string(nil), vv...)
	}
	bodyB64 := base64.StdEncoding.EncodeToString(body)
	p := cachedPayload{Status: status, Headers: h, BodyB64: bodyB64}
	val, err := json.Marshal(p)
	if err != nil {
		return
	}
	_ = r.client.Set(ctx, fullKey, val, ttl).Err()
}
