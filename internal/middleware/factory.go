package middleware

import (
	"cmp"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/redis"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Factory creates a Middleware from a configuration.
type Factory struct {
	redisClient redis.Client
	globalStore config.GlobalConfigStore
	ebpfManager ebpf.Manager
	dataDir     string
}

func NewFactory(redisClient redis.Client, globalStore config.GlobalConfigStore, ebpfManager ebpf.Manager, dataDir string) *Factory {
	return &Factory{redisClient: redisClient, globalStore: globalStore, ebpfManager: ebpfManager, dataDir: dataDir}
}

// Validate checks that the middleware config is valid without creating the middleware.
func (f *Factory) Validate(m *gateonv1.Middleware) error {
	_, err := f.Create(m, "")
	return err
}

func (f *Factory) Create(m *gateonv1.Middleware, routeID string) (Middleware, error) {
	cfg := make(map[string]string)
	for k, v := range m.Config {
		cfg[k] = config.ResolveSecret(v)
	}
	if routeID != "" {
		if _, ok := cfg["_route_id"]; !ok {
			cfg["_route_id"] = routeID
		}
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
		return f.createGRPCWeb(cfg)
	case "ipfilter":
		return f.createIPFilter(cfg)
	case "request_id":
		return RequestID(), nil
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
	case "oidc":
		return f.createOIDCProxy(cfg)
	case "graphql_firewall":
		return f.createGraphQLFirewall(cfg)
	case "bot_management":
		return f.createBotManagement(cfg)
	case "xss_recognition":
		return XSSRecognition(routeID), nil
	case "schema_validation":
		return SchemaValidation(SchemaValidationConfig{Schema: cfg["schema"]}), nil
	case "honeypot":
		return Honeypot(parseHoneypotConfig(cfg)), nil
	case "turnstile":
		return f.createTurnstile(cfg)
	case "geoip":
		return f.createGeoIP(cfg)
	case "hmac":
		return f.createHMAC(cfg)
	case "deception":
		return Deception(DeceptionConfig{
			HoneypotPaths:        parseListStrict(cmp.Or(cfg["honeypot_paths"], cfg["paths"])),
			InjectInvisibleLinks: parseBoolStrict(cmp.Or(cfg["inject_invisible_links"], "true"), true),
			InvisibleLinkPaths:   parseListStrict(cmp.Or(cfg["invisible_link_paths"], cfg["honey_links"])),
			HoneyForms:           parseListStrict(cfg["honey_forms"]),
			RouteID:              routeID,
			EnableTrollResponse:  parseBoolStrict(cfg["enable_troll_response"], false),
			CanaryHeader:         cfg["canary_header"],
			CanaryToken:          cfg["canary_token"],
		}), nil
	case "tarpit":
		baseDelay, _ := time.ParseDuration(cfg["base_delay"])
		maxDelay, _ := time.ParseDuration(cfg["max_delay"])
		threshold, _ := strconv.ParseFloat(cfg["threshold"], 64)
		return Tarpit(baseDelay, maxDelay, threshold), nil
	case "entropy":
		threshold, _ := strconv.ParseFloat(cfg["threshold"], 64)
		return Entropy(threshold, routeID), nil
	case "pow":
		difficulty, _ := strconv.Atoi(cfg["difficulty"])
		if difficulty == 0 {
			difficulty = 4
		}
		threshold, _ := strconv.ParseFloat(cfg["threshold"], 64)
		if threshold == 0 {
			threshold = 20.0
		}
		return Pow(difficulty, threshold, cfg["secret"], routeID), nil
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
	case "file_security":
		return f.createFileSecurity(cfg)
	case "tls_binding":
		cookieName := cfg["cookie_name"]
		if cookieName == "" {
			cookieName = "session"
		}
		return TlsBinding(cookieName), nil
	case "security_headers":
		return SecurityHeaders(SecurityHeadersConfig{Preset: cfg["preset"]}), nil
	case "wasm":
		return Wasm(context.Background(), m.WasmBlob)
	default:
		return nil, fmt.Errorf("unknown middleware type: %s", m.Type)
	}
}

func (f *Factory) createGRPCWeb(cfg map[string]string) (Middleware, error) {
	origins := parseListStrict(cfg["allowed_origins"])
	if len(origins) == 0 {
		return GRPCWeb(), nil
	}

	allowCredentials := parseBoolStrict(cfg["allow_credentials"], false)
	maxAge, _ := strconv.Atoi(cfg["max_age"])

	return GRPCWeb(CORSConfig{
		AllowedOrigins:   origins,
		AllowCredentials: allowCredentials,
		MaxAge:           maxAge,
	}), nil
}

func (f *Factory) createOIDCProxy(cfg map[string]string) (Middleware, error) {
	scopes := parseListStrict(cfg["scopes"])
	return OIDCProxy(OIDCProxyConfig{
		Issuer:       cfg["issuer"],
		ClientID:     cfg["client_id"],
		ClientSecret: cfg["client_secret"],
		RedirectURL:  cfg["redirect_url"],
		Scopes:       scopes,
		RouteID:      cfg["_route_id"],
	})
}

func (f *Factory) createFileSecurity(cfg map[string]string) (Middleware, error) {
	maxFileSize, _ := strconv.ParseInt(cfg["max_file_size"], 10, 64)
	clamavAddr := cfg["clamav_addr"]
	if clamavAddr == "" && f.globalStore != nil {
		if g := f.globalStore.Get(context.Background()); g != nil && g.Waf != nil {
			if g.Waf.Clamav != nil && g.Waf.Clamav.ClamavAddr != "" {
				clamavAddr = g.Waf.Clamav.ClamavAddr
			} else {
				clamavAddr = g.Waf.ClamavAddr
			}
		}
	}

	return FileSecurity(FileSecurityConfig{
		EnableClamAV:     parseBoolStrict(cfg["enable_clamav"], false),
		ClamAVAddr:       clamavAddr,
		BlockedMimeTypes: parseListStrict(cfg["blocked_mime_types"]),
		AllowedMimeTypes: parseListStrict(cfg["allowed_mime_types"]),
		MaxFileSize:      maxFileSize,
	}), nil
}
