package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/gateon/gateon/internal/redis"
	"github.com/gateon/gateon/internal/request"
	xrate "golang.org/x/time/rate"
)

// wafCache caches Coraza WAF instances by config hash to avoid repeated creation.
var wafCache sync.Map

// Factory creates a Middleware from a configuration.
type Factory struct {
	redisClient redis.Client
}

func NewFactory(redisClient redis.Client) *Factory {
	return &Factory{redisClient: redisClient}
}

// Validate checks that the middleware config is valid without creating the middleware.
// It reuses Create logic for consistency.
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

func (f *Factory) createRateLimit(cfg map[string]string) (Middleware, error) {
	rpm, _ := strconv.Atoi(cfg["requests_per_minute"])
	burst, _ := strconv.Atoi(cfg["burst"])
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

	trust := request.ParseTrustCloudflare(cfg["trust_cloudflare_headers"])
	keyFunc := PerIPWithTrust(trust)
	if perTenant {
		return limiter.Handler(PerTenant), nil
	}
	return limiter.Handler(keyFunc), nil
}

func (f *Factory) createAuth(cfg map[string]string) (Middleware, error) {
	authType := cfg["type"]
	switch authType {
	case "jwt":
		jwksURL := strings.TrimSpace(cfg["jwks_url"])
		secret := cfg["secret"]
		if secret == "" {
			secret = os.Getenv("GATEON_JWT_SECRET")
		}
		if jwksURL == "" && secret == "" {
			return nil, fmt.Errorf("jwt auth requires jwks_url or secret (or GATEON_JWT_SECRET env)")
		}
		jwtCfg := JWTConfig{
			Issuer:   cfg["issuer"],
			Audience: cfg["audience"],
			JWKSURL:  jwksURL,
			Secret:   []byte(secret),
		}
		validator, err := NewJWTValidator(jwtCfg)
		if err != nil {
			return nil, err
		}
		return validator.Handler, nil
	case "paseto":
		secret := cfg["secret"]
		if secret == "" {
			secret = os.Getenv("GATEON_PASETO_SECRET")
		}
		if secret == "" {
			return nil, fmt.Errorf("paseto auth requires config secret or GATEON_PASETO_SECRET env")
		}
		verifier, err := NewPasetoVerifier(secret)
		if err != nil {
			return nil, err
		}
		return PasetoAuth(verifier), nil
	case "apikey":
		keys := make(map[string]string)
		for k, v := range cfg {
			if strings.HasPrefix(k, "key_") {
				keys[strings.TrimPrefix(k, "key_")] = v
			}
		}
		if len(keys) == 0 {
			return nil, fmt.Errorf("apikey auth requires at least one key (key_name=value)")
		}
		headerName := cfg["header"]
		if headerName == "" {
			headerName = "X-API-Key"
		}
		return NewAPIKeyValidator(keys, headerName).Handler, nil
	case "basic":
		users := cfg["users"]
		if users == "" {
			// Single user: username + password
			username := cfg["username"]
			password := cfg["password"]
			if username == "" || password == "" {
				return nil, fmt.Errorf("basic auth requires username and password, or users (user:pass,user2:pass2)")
			}
			return BasicAuthWithRealm(username, password, cfg["realm"]), nil
		}
		return BasicAuthUsers(users, cfg["realm"])
	default:
		return nil, fmt.Errorf("unknown auth type: %s (use jwt, paseto, apikey, or basic)", authType)
	}
}

func (f *Factory) createHeaders(cfg map[string]string) (Middleware, error) {
	// HSTS (Traefik-style): sts_seconds, sts_include_subdomains, sts_preload, force_sts_header
	stsSeconds, _ := strconv.Atoi(cfg["sts_seconds"])
	stsIncludeSubdomains, _ := strconv.ParseBool(cfg["sts_include_subdomains"])
	stsPreload, _ := strconv.ParseBool(cfg["sts_preload"])
	forceSTSHeader, _ := strconv.ParseBool(cfg["force_sts_header"])

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

			// HSTS: add Strict-Transport-Security when sts_seconds > 0 and (TLS or force_sts_header)
			if stsSeconds > 0 && (r.TLS != nil || forceSTSHeader) {
				val := "max-age=" + strconv.Itoa(stsSeconds)
				if stsIncludeSubdomains {
					val += "; includeSubDomains"
				}
				if stsPreload {
					val += "; preload"
				}
				w.Header().Set("Strict-Transport-Security", val)
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

func (f *Factory) createIPFilter(cfg map[string]string) (Middleware, error) {
	parseList := func(key string) []string {
		val := cfg[key]
		if val == "" {
			return nil
		}
		var out []string
		for _, s := range strings.Split(val, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	allowList := parseList("allow_list")
	denyList := parseList("deny_list")
	trust := request.ParseTrustCloudflare(cfg["trust_cloudflare_headers"])
	clientIP := func(r *http.Request) string { return request.GetClientIP(r, trust) }
	return IPFilterWithClientIP(allowList, denyList, clientIP), nil
}

func (f *Factory) createCache(cfg map[string]string) (Middleware, error) {
	ttl, _ := strconv.Atoi(cfg["ttl_seconds"])
	maxEntries, _ := strconv.Atoi(cfg["max_entries"])
	maxBodyKB, _ := strconv.Atoi(cfg["max_body_kb"])
	storage := cfg["storage"]
	if storage == "" {
		storage = CacheStorageMemory
	}
	return Cache(CacheConfig{
		TTLSeconds:  ttl,
		MaxEntries:  maxEntries,
		MaxBodyKB:   int64(maxBodyKB),
		Storage:     storage,
		RedisClient: f.redisClient,
	}), nil
}

// createInflightReq creates a middleware that limits concurrent in-flight requests (Traefik-style).
// Config: amount (required), per_ip (default true).
func (f *Factory) createInflightReq(cfg map[string]string) (Middleware, error) {
	amount, _ := strconv.Atoi(cfg["amount"])
	if amount <= 0 {
		return nil, fmt.Errorf("inflightreq requires amount > 0")
	}
	perIP := true
	if v, ok := cfg["per_ip"]; ok {
		perIP, _ = strconv.ParseBool(v)
	}
	keyFunc := PerIP
	if !perIP {
		keyFunc = func(r *http.Request) string { return r.Host }
	}
	return MaxConnectionsPerIP(amount, keyFunc), nil
}

// createCompress creates a middleware that compresses responses with gzip (Traefik-style).
// Config: min_response_body_bytes, excluded_content_types, included_content_types, max_buffer_bytes.
func (f *Factory) createCompress(cfg map[string]string) (Middleware, error) {
	parseList := func(key string) []string {
		val := cfg[key]
		if val == "" {
			return nil
		}
		var out []string
		for _, s := range strings.Split(val, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	compressCfg := CompressConfig{
		MinResponseBodyBytes: parsePositiveInt(cfg["min_response_body_bytes"], 1024),
		ExcludedContentTypes: parseList("excluded_content_types"),
		IncludedContentTypes: parseList("included_content_types"),
		MaxBufferBytes:       parsePositiveInt(cfg["max_buffer_bytes"], 10*1024*1024),
	}
	return CompressWithConfig(compressCfg), nil
}

func parsePositiveInt(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return defaultVal
	}
	return n
}

// createForwardAuth creates a middleware that delegates auth to an external service (Traefik-style).
// Config: address (required), trust_forward_header, auth_response_headers, auth_request_headers,
// forward_body, preserve_request_method, max_body_size, tls_insecure_skip_verify
func (f *Factory) createForwardAuth(cfg map[string]string) (Middleware, error) {
	parseList := func(key string) []string {
		val := cfg[key]
		if val == "" {
			return nil
		}
		var out []string
		for _, s := range strings.Split(val, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	maxBody := int64(1024 * 1024) // 1MB default
	if v := cfg["max_body_size"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			maxBody = n
		}
	}
	forwardCfg := ForwardAuthConfig{
		Address:               strings.TrimSpace(cfg["address"]),
		TrustForwardHeader:    parseBool(cfg["trust_forward_header"], false),
		AuthResponseHeaders:   parseList("auth_response_headers"),
		AuthRequestHeaders:   parseList("auth_request_headers"),
		ForwardBody:           parseBool(cfg["forward_body"], false),
		PreserveRequestMethod: parseBool(cfg["preserve_request_method"], false),
		MaxBodySize:           maxBody,
		TLSInsecureSkipVerify: parseBool(cfg["tls_insecure_skip_verify"], false),
	}
	return ForwardAuth(forwardCfg)
}

func parseBool(s string, defaultVal bool) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return defaultVal
	}
	return s == "true" || s == "1" || s == "yes"
}

func (f *Factory) createWAF(cfg map[string]string) (Middleware, error) {
	key := wafConfigKey(cfg)
	if cached, ok := wafCache.Load(key); ok {
		return cached.(Middleware), nil
	}
	mw, err := WAF(parseWAFConfig(cfg))
	if err != nil {
		return nil, err
	}
	wafCache.Store(key, mw)
	return mw, nil
}

// InvalidateWAFCache clears all cached WAF instances. Call when a WAF middleware is saved or deleted.
func InvalidateWAFCache() {
	wafCache.Range(func(key, _ interface{}) bool {
		wafCache.Delete(key)
		return true
	})
}

// WAFCacheInvalidator implements domain.WAFCacheInvalidator by clearing the WAF cache.
type WAFCacheInvalidator struct{}

// Invalidate clears all cached WAF instances.
func (WAFCacheInvalidator) Invalidate() {
	InvalidateWAFCache()
}

func wafConfigKey(cfg map[string]string) string {
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(cfg[k])
		b.WriteByte(';')
	}
	h := sha256.Sum256([]byte(b.String()))
	return "waf:" + hex.EncodeToString(h[:])
}

func (f *Factory) createGeoIP(cfg map[string]string) (Middleware, error) {
	parseList := func(key string) []string {
		val := cfg[key]
		if val == "" {
			return nil
		}
		var out []string
		for _, s := range strings.Split(val, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return GeoIP(GeoIPConfig{
		DBPath:          strings.TrimSpace(cfg["db_path"]),
		AllowCountries:  parseList("allow_countries"),
		DenyCountries:   parseList("deny_countries"),
		TrustCloudflare: request.ParseTrustCloudflare(cfg["trust_cloudflare_headers"]),
	})
}

func (f *Factory) createTurnstile(cfg map[string]string) (Middleware, error) {
	secret := strings.TrimSpace(cfg["secret"])
	if secret == "" {
		secret = os.Getenv("GATEON_TURNSTILE_SECRET")
	}
	if secret == "" {
		return nil, fmt.Errorf("turnstile requires secret or GATEON_TURNSTILE_SECRET env")
	}
	headerName := cfg["header"]
	if headerName == "" {
		headerName = "CF-Turnstile-Response"
	}
	methods := cfg["methods"]
	if methods == "" {
		methods = "POST,PUT,PATCH,DELETE"
	}
	return Turnstile(TurnstileConfig{
		Secret:       secret,
		HeaderName:   strings.TrimSpace(headerName),
		Methods:      strings.Split(methods, ","),
	}), nil
}

func (f *Factory) createHMAC(cfg map[string]string) (Middleware, error) {
	secret := strings.TrimSpace(cfg["secret"])
	if secret == "" {
		secret = os.Getenv("GATEON_HMAC_SECRET")
	}
	if secret == "" {
		return nil, fmt.Errorf("hmac requires secret or GATEON_HMAC_SECRET env")
	}
	header := cfg["header"]
	if header == "" {
		header = "X-Signature-256"
	}
	prefix := cfg["prefix"]
	if prefix == "" {
		prefix = "sha256="
	}
	methods := cfg["methods"]
	var methodList []string
	if methods != "" {
		for _, m := range strings.Split(methods, ",") {
			m = strings.TrimSpace(strings.ToUpper(m))
			if m != "" {
				methodList = append(methodList, m)
			}
		}
	}
	bodyLimit := int64(1024 * 1024)
	if v := cfg["body_limit"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			bodyLimit = n
		}
	}
	return HMAC(HMACConfig{
		Secret:    secret,
		Header:    header,
		Prefix:    prefix,
		Methods:   methodList,
		BodyLimit: bodyLimit,
	})
}

// createBuffering creates a middleware that limits request body size (Traefik-style).
// Config: max_request_body_bytes (required).
func (f *Factory) createBuffering(cfg map[string]string) (Middleware, error) {
	s := cfg["max_request_body_bytes"]
	if s == "" {
		return nil, fmt.Errorf("buffering requires max_request_body_bytes")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return nil, fmt.Errorf("buffering max_request_body_bytes must be a positive integer")
	}
	return MaxBodySize(n), nil
}
