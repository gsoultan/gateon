package middleware

import (
	"cmp"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/redis"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Factory creates a Middleware from a configuration.
type Factory struct {
	redisClient redis.Client
	globalStore config.GlobalConfigStore
}

func NewFactory(redisClient redis.Client, globalStore config.GlobalConfigStore) *Factory {
	return &Factory{redisClient: redisClient, globalStore: globalStore}
}

// Validate checks that the middleware config is valid without creating the middleware.
func (f *Factory) Validate(m *gateonv1.Middleware) error {
	_, err := f.Create(m)
	return err
}

func (f *Factory) Create(m *gateonv1.Middleware) (Middleware, error) {
	cfg := make(map[string]string)
	for k, v := range m.Config {
		cfg[k] = config.ResolveSecret(v)
	}

	switch m.Type {
	case "ratelimit":
		return f.createRateLimit(cfg)
	case "auth":
		return f.createAuth(cfg)
	case "headers":
		return f.createHeaders(cfg)
	case "rewrite":
		return f.createRewrite(cfg)
	case "addprefix":
		return AddPrefix(cfg["prefix"]), nil
	case "stripprefix":
		prefixes := strings.Split(cfg["prefixes"], ",")
		return StripPrefix(prefixes), nil
	case "stripprefixregex":
		return StripPrefixRegex(cfg["regex"])
	case "replacepath":
		return ReplacePath(cfg["path"]), nil
	case "replacepathregex":
		return ReplacePathRegex(cfg["pattern"], cfg["replacement"])
	case "accesslog":
		return AccessLog(cmp.Or(cfg["route"], cfg["route_id"])), nil
	case "metrics":
		return Metrics(cmp.Or(cfg["route"], cfg["route_id"])), nil
	case "compress":
		return f.createCompress(cfg)
	case "errors":
		intCodes := make([]int, 0)
		pages := make(map[int]string)
		for c := range strings.SplitSeq(cfg["status_codes"], ",") {
			if ic, err := strconv.Atoi(strings.TrimSpace(c)); err == nil {
				intCodes = append(intCodes, ic)
				if page, ok := cfg[fmt.Sprintf("page_%d", ic)]; ok {
					pages[ic] = page
				}
			}
		}
		return Errors(ErrorsConfig{StatusCodes: intCodes, CustomPages: pages}), nil
	case "retry":
		attempts, _ := strconv.Atoi(cfg["attempts"])
		return Retry(RetryConfig{Attempts: attempts}), nil
	case "cors":
		return f.createCORS(cfg)
	case "grpcweb":
		return GRPCWeb(), nil
	case "ipfilter":
		return f.createIPFilter(cfg)
	case "cache":
		return f.createCache(cfg)
	case "inflightreq":
		return f.createInflightReq(cfg)
	case "buffering":
		return f.createBuffering(cfg)
	case "forwardauth":
		return f.createForwardAuth(cfg)
	case "waf":
		return f.createWAF(cfg)
	case "turnstile":
		return f.createTurnstile(cfg)
	case "geoip":
		return f.createGeoIP(cfg)
	case "hmac":
		return f.createHMAC(cfg)
	case "policy":
		return f.createPolicy(cfg)
	case "xfcc":
		return f.createXFCC(cfg)
	case "transform":
		return BodyTransform(BodyTransformConfig{
			RequestSearch:     cfg["request_search"],
			RequestReplace:    cfg["request_replace"],
			ResponseSearch:    cfg["response_search"],
			ResponseReplace:   cfg["response_replace"],
			ContentTypeFilter: cfg["content_type"],
		}), nil
	case "wasm":
		return Wasm(context.Background(), m.WasmBlob)
	default:
		return nil, fmt.Errorf("unknown middleware type: %s", m.Type)
	}
}
