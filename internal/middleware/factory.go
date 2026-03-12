package middleware

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/redis/go-redis/v9"
	xrate "golang.org/x/time/rate"
)

// Factory creates a Middleware from a configuration.
type Factory struct {
	redisClient *redis.Client
}

func NewFactory(redisClient *redis.Client) *Factory {
	return &Factory{redisClient: redisClient}
}

func (f *Factory) Create(m *gateonv1.Middleware) (Middleware, error) {
	switch m.Type {
	case "ratelimit":
		return f.createRateLimit(m.Config)
	case "auth":
		return f.createAuth(m.Config)
	case "headers":
		return f.createHeaders(m.Config)
	case "rewrite":
		return f.createRewrite(m.Config)
	case "addprefix":
		return AddPrefix(m.Config["prefix"]), nil
	case "stripprefix":
		prefixes := strings.Split(m.Config["prefixes"], ",")
		return StripPrefix(prefixes), nil
	case "stripprefixregex":
		return StripPrefixRegex(m.Config["regex"])
	case "replacepath":
		return ReplacePath(m.Config["path"]), nil
	case "replacepathregex":
		return ReplacePathRegex(m.Config["pattern"], m.Config["replacement"])
	case "accesslog":
		return AccessLog(m.Config["route_id"]), nil
	case "metrics":
		return Metrics(m.Config["route_id"]), nil
	case "compress":
		return Compress(), nil
	case "errors":
		intCodes := make([]int, 0)
		pages := make(map[int]string)
		for c := range strings.SplitSeq(m.Config["status_codes"], ",") {
			if ic, err := strconv.Atoi(strings.TrimSpace(c)); err == nil {
				intCodes = append(intCodes, ic)
				if page, ok := m.Config[fmt.Sprintf("page_%d", ic)]; ok {
					pages[ic] = page
				}
			}
		}
		return Errors(ErrorsConfig{StatusCodes: intCodes, CustomPages: pages}), nil
	case "retry":
		attempts, _ := strconv.Atoi(m.Config["attempts"])
		return Retry(RetryConfig{Attempts: attempts}), nil
	case "cors":
		return f.createCORS(m.Config)
	case "grpcweb":
		return GRPCWeb(), nil
	default:
		return nil, fmt.Errorf("unknown middleware type: %s", m.Type)
	}
}

func (f *Factory) createRateLimit(cfg map[string]string) (Middleware, error) {
	rpm, _ := strconv.Atoi(cfg["requests_per_minute"])
	burst, _ := strconv.Atoi(cfg["burst"])
	perIp, _ := strconv.ParseBool(cfg["per_ip"])
	perTenant, _ := strconv.ParseBool(cfg["per_tenant"])
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

	if perTenant {
		return limiter.Handler(PerTenant), nil
	}
	if perIp {
		return limiter.Handler(PerIP), nil
	}
	return limiter.Handler(PerIP), nil
}

func (f *Factory) createAuth(cfg map[string]string) (Middleware, error) {
	authType := cfg["type"]
	switch authType {
	case "jwt":
		secret := cfg["secret"]
		if secret == "" {
			secret = os.Getenv("GATEON_JWT_SECRET")
		}
		if secret == "" {
			return nil, fmt.Errorf("jwt auth requires config secret or GATEON_JWT_SECRET env")
		}
		validator, err := NewJWTValidator(JWTConfig{
			Issuer:   cfg["issuer"],
			Audience: cfg["audience"],
			Secret:   []byte(secret),
		})
		if err != nil {
			return nil, err
		}
		return validator.Handler, nil
	case "apikey":
		keys := make(map[string]string)
		for k, v := range cfg {
			if strings.HasPrefix(k, "key_") {
				keys[strings.TrimPrefix(k, "key_")] = v
			}
		}
		return NewAPIKeyValidator(keys).Handler, nil
	default:
		return nil, fmt.Errorf("unknown auth type: %s", authType)
	}
}

func (f *Factory) createHeaders(cfg map[string]string) (Middleware, error) {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for k, v := range cfg {
				if strings.HasPrefix(k, "add_request_") {
					r.Header.Add(strings.TrimPrefix(k, "add_request_"), v)
				} else if strings.HasPrefix(k, "set_request_") {
					r.Header.Set(strings.TrimPrefix(k, "set_request_"), v)
				} else if strings.HasPrefix(k, "del_request_") {
					r.Header.Del(strings.TrimPrefix(k, "del_request_"))
				}
			}

			sw := &StatusResponseWriter{ResponseWriter: w, Status: http.StatusOK}
			next.ServeHTTP(sw, r)

			for k, v := range cfg {
				if strings.HasPrefix(k, "add_response_") {
					w.Header().Add(strings.TrimPrefix(k, "add_response_"), v)
				} else if strings.HasPrefix(k, "set_response_") {
					w.Header().Set(strings.TrimPrefix(k, "set_response_"), v)
				} else if strings.HasPrefix(k, "del_response_") {
					w.Header().Del(strings.TrimPrefix(k, "del_response_"))
				}
			}
		})
	}, nil
}

func (f *Factory) createRewrite(cfg map[string]string) (Middleware, error) {
	rewriteCfg := RewriteConfig{
		Path:     cfg["path"],
		AddQuery: make(map[string]string),
	}

	if pattern := cfg["pattern"]; pattern != "" {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid rewrite pattern: %w", err)
		}
		rewriteCfg.Regexp = re
		rewriteCfg.Replacement = cfg["replacement"]
	}

	for k, v := range cfg {
		if strings.HasPrefix(k, "query_") {
			rewriteCfg.AddQuery[strings.TrimPrefix(k, "query_")] = v
		}
	}

	return Rewrite(rewriteCfg), nil
}

func (f *Factory) createCORS(cfg map[string]string) (Middleware, error) {
	parseList := func(key string) []string {
		val := cfg[key]
		if val == "" {
			return nil
		}
		parts := strings.Split(val, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		return parts
	}

	allowCredentials, _ := strconv.ParseBool(cfg["allow_credentials"])
	maxAge, _ := strconv.Atoi(cfg["max_age"])

	return CORS(CORSConfig{
		AllowedOrigins:   parseList("allowed_origins"),
		AllowedMethods:   parseList("allowed_methods"),
		AllowedHeaders:   parseList("allowed_headers"),
		ExposedHeaders:   parseList("exposed_headers"),
		AllowCredentials: allowCredentials,
		MaxAge:           maxAge,
	}), nil
}
