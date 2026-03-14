package middleware

import (
	"github.com/gateon/gateon/internal/request"
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
		limiter = NewRateLimiter(xrate.Limit(rateVal), burst)
	}

	trust := request.ParseTrustCloudflare(cfg["trust_cloudflare_headers"])
	keyFunc := PerIPWithTrust(trust)
	if perTenant {
		return limiter.Handler(PerTenant), nil
	}
	return limiter.Handler(keyFunc), nil
}
