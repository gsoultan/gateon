package middleware

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/request"
	xrate "golang.org/x/time/rate"
)

func (f *Factory) createRateLimit(cfg map[string]string) (Middleware, error) {
	rpm, _ := strconvParseInt(cfg["requests_per_minute"], 60)
	burst, _ := strconvParseInt(cfg["burst"], 5)
	perTenant := parseBoolStrict(cfg["per_tenant"], false)
	storage := cfg["storage"]

	var limiter RateLimiter
	if storage == "redis" && f.redisClient != nil {
		limiter = NewRedisRateLimiter(f.redisClient, rpm, burst)
	} else {
		rateVal := float64(rpm) / 60.0
		if rateVal <= 0 {
			rateVal = 1.0
		}
		if burst <= 0 {
			burst = 5
		}
		limiter = NewRateLimiterWithEbpf(xrate.Limit(rateVal), burst, f.ebpfManager)
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
