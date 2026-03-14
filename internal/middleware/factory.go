package middleware

import (
	"fmt"
	"strconv"
	"strings"

	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/gateon/gateon/internal/redis"
)

// Factory creates a Middleware from a configuration.
type Factory struct {
	redisClient redis.Client
}

func NewFactory(redisClient redis.Client) *Factory {
	return &Factory{redisClient: redisClient}
}

// Validate checks that the middleware config is valid without creating the middleware.
func (f *Factory) Validate(m *gateonv1.Middleware) error {
	_, err := f.Create(m)
	return err
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
		return f.createCompress(m.Config)
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
	case "ipfilter":
		return f.createIPFilter(m.Config)
	case "cache":
		return f.createCache(m.Config)
	case "inflightreq":
		return f.createInflightReq(m.Config)
	case "buffering":
		return f.createBuffering(m.Config)
	case "forwardauth":
		return f.createForwardAuth(m.Config)
	case "waf":
		return f.createWAF(m.Config)
	case "turnstile":
		return f.createTurnstile(m.Config)
	case "geoip":
		return f.createGeoIP(m.Config)
	case "hmac":
		return f.createHMAC(m.Config)
	default:
		return nil, fmt.Errorf("unknown middleware type: %s", m.Type)
	}
}
