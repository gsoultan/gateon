// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"errors"
	"net/http"

	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/internal/request"
	xrate "golang.org/x/time/rate"
)

func NewRateLimit(cfg map[string]string, redisClient redis.Client, ebpfManager ebpf.Manager) (kind.Middleware, error) {
	rpm, err := kind.ParseIntStrict(cfg["requests_per_minute"], 60)
	if err != nil {
		return nil, kind.CfgError("requests_per_minute", cfg["requests_per_minute"], err)
	}
	burst, err := kind.ParseIntStrict(cfg["burst"], 5)
	if err != nil {
		return nil, kind.CfgError("burst", cfg["burst"], err)
	}
	perTenant, err := kind.ParseBoolStrict(cfg["per_tenant"], false)
	if err != nil {
		return nil, kind.CfgError("per_tenant", cfg["per_tenant"], err)
	}
	storage := cfg["storage"]

	var limiter RateLimiter
	if storage == "redis" && redisClient != nil {
		rl := NewRedisRateLimiter(redisClient, rpm, burst)
		rl.namespace = cfg[kind.RouteStateKey] + "/" + cfg[kind.MiddlewareIDKey]
		limiter = rl
	} else {
		if storage == "redis" {
			// A save is refused (CheckRateLimitSave); a config stored before
			// that, or one whose gateway has since lost its Redis, still
			// limits -- per instance, which on one node is the limit asked for.
			logger.L.LogWarn("ratelimit: storage is redis but this gateway has no Redis; counting in this "+
				"instance's memory, so each instance allows the full limit",
				"middleware", cfg[kind.MiddlewareIDKey], "effective_storage", "local")
		}
		rateVal := float64(rpm) / 60.0
		if rateVal <= 0 {
			rateVal = 1.0
		}
		if burst <= 0 {
			burst = 5
		}
		limiter = NewRateLimiterWithEbpf(xrate.Limit(rateVal), burst, ebpfManager)
	}

	strategy := cfg["strategy"]
	var keyFunc func(*http.Request) string

	switch strategy {
	case "tenant":
		keyFunc = PerTenant
	case "ja4h":
		keyFunc = PerJA4H
	case "fingerprint":
		keyFunc = PerFingerprint
	default:
		// The address the entrypoint resolved, under the gateway's trust
		// setting (invariant 8). trust_cloudflare_headers here is not read:
		// it never changed the key, and a save that disagrees with the
		// global setting is refused (ADR 0046).
		keyFunc = request.ClientAddr
	}

	if perTenant { // compatibility for older configs
		keyFunc = PerTenant
	}

	return limiter.Handler(keyFunc), nil
}

// CheckRateLimitSave refuses storage=redis on a gateway with no Redis (ADR
// 0046). It fell back to each instance's memory with no word, so N instances
// allowed N times the limit the dashboard showed as shared.
func CheckRateLimitSave(cfg map[string]string, haveRedis bool) error {
	if cfg["storage"] != "redis" || haveRedis {
		return nil
	}
	return kind.CfgError("storage", "redis", errors.New("this gateway has no Redis configured, so the count "+
		"would be kept in each instance's memory and every instance would allow the full limit; configure "+
		"Redis in Settings and restart, or choose local storage"))
}
