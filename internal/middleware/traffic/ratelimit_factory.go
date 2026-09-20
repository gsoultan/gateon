// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/internal/request"
	xrate "golang.org/x/time/rate"
)

func NewRateLimit(cfg map[string]string, redisClient redis.Client, ebpfManager ebpf.Manager) (kind.Middleware, error) {
	rpm, _ := kind.ParseIntStrict(cfg["requests_per_minute"], 60)
	burst, _ := kind.ParseIntStrict(cfg["burst"], 5)
	perTenant := kind.ParseBoolStrict(cfg["per_tenant"], false)
	storage := cfg["storage"]

	var limiter RateLimiter
	if storage == "redis" && redisClient != nil {
		limiter = NewRedisRateLimiter(redisClient, rpm, burst)
	} else {
		rateVal := float64(rpm) / 60.0
		if rateVal <= 0 {
			rateVal = 1.0
		}
		if burst <= 0 {
			burst = 5
		}
		limiter = NewRateLimiterWithEbpf(xrate.Limit(rateVal), burst, ebpfManager)
	}

	trust := request.ParseTrustCloudflare(cfg["trust_cloudflare_headers"])
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
		keyFunc = PerIPWithTrust(trust)
	}

	if perTenant { // compatibility for older configs
		keyFunc = PerTenant
	}

	return limiter.Handler(keyFunc), nil
}
