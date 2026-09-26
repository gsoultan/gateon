// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	redigo "github.com/redis/go-redis/v9"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Every per-route middleware state was keyed by the route's label -- its name,
// or its ID when it has none -- and nothing stops two routes having the same
// name. Two routes both called "api" shared one circuit breaker: one route's
// failing backend opened the breaker, and the other route, whose backend was
// healthy, answered 503.
func TestRoutesWithTheSameNameDoNotShareACircuitBreaker(t *testing.T) {
	mws := map[string]*gateonv1.Middleware{"cb": {Id: "cb", Type: "circuit_breaker", Config: map[string]string{
		"min_requests": "2", "error_threshold": "0.5", "sleep_window": "1m",
	}}}
	failing := sameNameRoute(t, "state-a", statusBackend(http.StatusInternalServerError), mws, nil)
	healthy := sameNameRoute(t, "state-b", statusBackend(http.StatusOK), mws, nil)

	for range 3 {
		serveRoute(failing, "/")
	}
	if code := serveRoute(failing, "/").Code; code != http.StatusServiceUnavailable {
		t.Fatalf("control: route a's breaker did not open (got %d), so this test would prove nothing", code)
	}
	if code := serveRoute(healthy, "/").Code; code != http.StatusOK {
		t.Fatalf("route b, whose backend is healthy, answered %d: it shares a breaker with route a "+
			"because both are named %q", code, "api")
	}
}

// The Redis cache is shared by every route on every instance, so its keys carry
// the route. They carried the label, so two routes named alike served each
// other's cached responses for the same host and path -- routes that differ
// only by a header or a method are exactly that.
func TestRoutesWithTheSameNameDoNotShareRedisCacheEntries(t *testing.T) {
	shared := newMemRedis()
	mws := map[string]*gateonv1.Middleware{"cache": {Id: "cache", Type: "cache", Config: map[string]string{
		"storage": "redis", "ttl_seconds": "60",
	}}}
	a := sameNameRoute(t, "state-a", bodyBackend("route a's data"), mws, shared)
	b := sameNameRoute(t, "state-b", bodyBackend("route b's data"), mws, shared)

	if got := serveRoute(a, "/report").Body.String(); got != "route a's data" {
		t.Fatalf("control: route a answered %q", got)
	}
	if got := serveRoute(b, "/report").Body.String(); got != "route b's data" {
		t.Fatalf("route b answered with %q from the cache: it shares cache entries with route a", got)
	}
}

// The Redis rate limiter kept one window per client -- "ratelimit:v2:<ip>" --
// for every route and every rate-limit middleware in the cluster. Requests to
// one route counted against another's limit, and a route with two limiters
// counted each request twice.
func TestRedisRateLimitsAreKeptPerRouteAndMiddleware(t *testing.T) {
	shared := newMemRedis()
	limit := map[string]string{"storage": "redis", "requests_per_minute": "1", "burst": "1"}
	one := map[string]*gateonv1.Middleware{"rl": {Id: "rl", Type: "ratelimit", Config: limit}}
	a := sameNameRoute(t, "state-a", statusBackend(http.StatusOK), one, shared)
	b := sameNameRoute(t, "state-b", statusBackend(http.StatusOK), one, shared)

	for range 2 {
		serveRoute(a, "/")
	}
	if code := serveRoute(a, "/").Code; code != http.StatusTooManyRequests {
		t.Fatalf("control: route a's limit of 2 a minute did not refuse a third request (got %d)", code)
	}
	if code := serveRoute(b, "/").Code; code != http.StatusOK {
		t.Fatalf("the first request to route b was refused (%d): it counted route a's requests", code)
	}

	two := map[string]*gateonv1.Middleware{
		"rl":  {Id: "rl", Type: "ratelimit", Config: limit},
		"rl2": {Id: "rl2", Type: "ratelimit", Config: limit},
	}
	c := sameNameRoute(t, "state-c", statusBackend(http.StatusOK), two, shared)
	for i := range 2 {
		if code := serveRoute(c, "/").Code; code != http.StatusOK {
			t.Fatalf("request %d of 2 to a route with two limits of 2 a minute was refused (%d): the "+
				"limiters count each request in one window", i+1, code)
		}
	}
}

// sameNameRoute builds a route with the given ID, named "api" like every
// other route here, in front of backend, with every middleware in mws.
func sameNameRoute(t *testing.T, id string, backend http.Handler, mws map[string]*gateonv1.Middleware, rdb redis.Client) http.Handler {
	t.Helper()
	upstream := httptest.NewServer(backend)
	t.Cleanup(upstream.Close)
	services := config.NewServiceRegistry(filepath.Join(t.TempDir(), "services.json"))
	if err := services.Update(context.Background(), &gateonv1.Service{
		Id: "svc-" + id, WeightedTargets: []*gateonv1.Target{{Url: upstream.URL, Weight: 1}},
	}); err != nil {
		t.Fatalf("update service: %v", err)
	}
	rt := &gateonv1.Route{Id: id, Name: "api", ServiceId: "svc-" + id, Rule: "PathPrefix(`/`)", Type: "http"}
	for mid := range mws {
		rt.Middlewares = append(rt.Middlewares, mid)
	}
	ph := proxy.NewProxyHandler(rt, services)
	t.Cleanup(ph.Close)
	chain := ApplyRouteMiddlewares(ph, rt, rdb, fakeMWStore{m: mws}, fakeGlobalStore{cfg: &gateonv1.GlobalConfig{}}, nil, nil)
	return middleware.EntryPoint("web", "web", false)(chain)
}

func serveRoute(h http.Handler, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com"+path, nil)
	req.RemoteAddr = "203.0.113.7:4000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func statusBackend(code int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })
}

func bodyBackend(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = io.WriteString(w, body)
	})
}

// memRedis is the part of Redis the cache and the rate limiter use: strings
// and sorted-set cardinality. The embedded nil Cmdable covers the rest of the
// interface and panics if the code under test reaches for it.
type memRedis struct {
	redigo.Cmdable
	mu      sync.Mutex
	strings map[string]string
	sets    map[string]map[string]struct{}
}

func newMemRedis() *memRedis {
	return &memRedis{strings: map[string]string{}, sets: map[string]map[string]struct{}{}}
}

func (m *memRedis) Get(_ context.Context, key string) *redigo.StringCmd {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.strings[key]
	if !ok {
		return redigo.NewStringResult("", redigo.Nil)
	}
	return redigo.NewStringResult(v, nil)
}

func (m *memRedis) Set(_ context.Context, key string, value any, _ time.Duration) *redigo.StatusCmd {
	b, ok := value.([]byte)
	if !ok {
		return redigo.NewStatusResult("", errors.New("memRedis: value is not []byte"))
	}
	m.mu.Lock()
	m.strings[key] = string(b)
	m.mu.Unlock()
	return redigo.NewStatusResult("OK", nil)
}

func (m *memRedis) Pipeline() redigo.Pipeliner { return &memPipe{m: m} }

func (m *memRedis) Subscribe(context.Context, ...string) *redigo.PubSub { return nil }

func (m *memRedis) Close() error { return nil }

// memPipe runs the rate limiter's pipeline: ZRemRangeByScore, ZAdd, ZCard,
// Expire. The window never slides here -- a test is shorter than a minute.
type memPipe struct {
	redigo.Pipeliner
	m    *memRedis
	cmds []redigo.Cmder
	ops  []func()
}

func (p *memPipe) ZRemRangeByScore(ctx context.Context, key, _, _ string) *redigo.IntCmd {
	cmd := redigo.NewIntCmd(ctx, "zremrangebyscore", key)
	p.cmds = append(p.cmds, cmd)
	return cmd
}

func (p *memPipe) ZAdd(ctx context.Context, key string, members ...redigo.Z) *redigo.IntCmd {
	cmd := redigo.NewIntCmd(ctx, "zadd", key)
	p.cmds = append(p.cmds, cmd)
	p.ops = append(p.ops, func() {
		set := p.m.sets[key]
		if set == nil {
			set = map[string]struct{}{}
			p.m.sets[key] = set
		}
		for _, z := range members {
			member, _ := z.Member.(string)
			set[member] = struct{}{}
		}
	})
	return cmd
}

func (p *memPipe) ZCard(ctx context.Context, key string) *redigo.IntCmd {
	cmd := redigo.NewIntCmd(ctx, "zcard", key)
	p.cmds = append(p.cmds, cmd)
	p.ops = append(p.ops, func() { cmd.SetVal(int64(len(p.m.sets[key]))) })
	return cmd
}

func (p *memPipe) Expire(ctx context.Context, key string, _ time.Duration) *redigo.BoolCmd {
	cmd := redigo.NewBoolCmd(ctx, "expire", key)
	p.cmds = append(p.cmds, cmd)
	return cmd
}

func (p *memPipe) Exec(context.Context) ([]redigo.Cmder, error) {
	p.m.mu.Lock()
	defer p.m.mu.Unlock()
	for _, op := range p.ops {
		op()
	}
	return p.cmds, nil
}
