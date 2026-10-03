// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Two settings that saved and did something else (ADR 0046): a rate limit's
// "Storage: Redis" fell back to a per-instance counter when the gateway had no
// Redis, so N instances allowed N times the limit; and the per-middleware
// "Trust Cloudflare Headers" switch was ignored, because the entrypoint
// resolves the client address once, under the global setting, for every
// middleware.

// TestRateLimitRedisStorageWithoutRedisIsRefusedAtSave saves Storage: Redis on
// a gateway with no Redis.
func TestRateLimitRedisStorageWithoutRedisIsRefusedAtSave(t *testing.T) {
	m := &gateonv1.Middleware{Id: "rl", Type: "ratelimit", Config: map[string]string{
		"requests_per_minute": "60", "storage": "redis",
	}}
	err := NewFactory(nil, nil, nil, nil, t.TempDir()).Validate(m)
	if err == nil {
		t.Fatal("storage=redis saved on a gateway with no Redis; it would count per instance, not across them")
	}
	if !strings.Contains(err.Error(), "Redis") {
		t.Errorf("refusal %q does not name Redis", err)
	}
	with := NewFactory(newRevocationRedis(), nil, nil, nil, t.TempDir())
	if err := with.Validate(m); err != nil {
		t.Errorf("storage=redis refused on a gateway with Redis: %v", err)
	}
	m.Config["storage"] = "local"
	if err := NewFactory(nil, nil, nil, nil, t.TempDir()).Validate(m); err != nil {
		t.Errorf("storage=local refused: %v", err)
	}
}

// TestRateLimitStoredRedisStorageStillLimitsWithoutRedis: a config saved
// before the refusal keeps limiting, in this instance's memory, rather than
// taking its route out of service.
func TestRateLimitStoredRedisStorageStillLimitsWithoutRedis(t *testing.T) {
	mw, err := NewFactory(nil, nil, nil, nil, t.TempDir()).Create(&gateonv1.Middleware{
		Id: "rl", Type: "ratelimit",
		Config: map[string]string{"requests_per_minute": "60", "burst": "1", "storage": "redis"},
	}, "route")
	if err != nil {
		t.Fatalf("a stored storage=redis config no longer builds: %v", err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	var codes []int
	for range 3 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "198.51.100.7:1000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
	}
	if codes[0] != http.StatusOK || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("codes = %v, want 200 then 429: the fallback must still limit", codes)
	}
}

// trustStore is a global config whose Cloudflare trust is on or off.
func trustStore(on bool) *mockGlobalConfigStore {
	return &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{TrustCloudflareHeaders: on}}}
}

// TestPerMiddlewareCloudflareTrustThatDisagreesIsRefusedAtSave: the switch can
// only ever say what the global setting says, so a value that says otherwise
// is refused, naming the setting that decides.
func TestPerMiddlewareCloudflareTrustThatDisagreesIsRefusedAtSave(t *testing.T) {
	if request.TrustCloudflareFromEnv() {
		t.Skip("GATEON_TRUST_CLOUDFLARE_HEADERS is set for this process; trust cannot be off")
	}
	base := map[string]map[string]string{
		"ratelimit": {"requests_per_minute": "60"},
		"ipfilter":  {"allow_list": "203.0.113.0/24"},
		"geoip":     {"deny_countries": "XX"},
	}
	for typ, cfg := range base {
		for _, tc := range []struct {
			global  bool
			value   string
			refused bool
		}{
			{false, "true", true}, {true, "false", true},
			{false, "false", false}, {true, "true", false}, {false, "", false},
		} {
			c := map[string]string{"trust_cloudflare_headers": tc.value}
			for k, v := range cfg {
				c[k] = v
			}
			err := NewFactory(nil, trustStore(tc.global), nil, nil, t.TempDir()).
				Validate(&gateonv1.Middleware{Id: "m", Type: typ, Config: c})
			switch {
			case tc.refused && err == nil:
				t.Errorf("%s trust_cloudflare_headers=%q with global trust %v saved; the switch would be ignored",
					typ, tc.value, tc.global)
			case tc.refused && !strings.Contains(err.Error(), "Trust Cloudflare"):
				t.Errorf("%s: refusal %q does not name the global setting", typ, err)
			case !tc.refused && err != nil && strings.Contains(err.Error(), "trust_cloudflare_headers"):
				t.Errorf("%s trust_cloudflare_headers=%q agreeing with global %v refused: %v", typ, tc.value, tc.global, err)
			}
		}
	}
}

// TestRateLimitKeysOnTheResolvedClientAddress: the rate limiter keys on the
// address the entrypoint resolved, whatever its own trust switch says.
func TestRateLimitKeysOnTheResolvedClientAddress(t *testing.T) {
	mw, err := NewFactory(nil, nil, nil, nil, t.TempDir()).Create(&gateonv1.Middleware{
		Id: "rl", Type: "ratelimit",
		Config: map[string]string{"requests_per_minute": "60", "burst": "1", "trust_cloudflare_headers": "true"},
	}, "route")
	if err != nil {
		t.Fatal(err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	for i, client := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "173.245.48.10:443" // a Cloudflare edge
		req.Header.Set("CF-Connecting-IP", "198.51.100.99")
		req = req.WithContext(request.WithState(req.Context(), &request.RequestState{ClientRemoteAddr: client}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d from resolved client %s got %d: the limiter did not key on the resolved address", i, client, rec.Code)
		}
	}
}
