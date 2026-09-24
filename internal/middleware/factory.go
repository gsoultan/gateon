// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"cmp"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/middleware/security"
	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/middleware/security/waf"
	"github.com/gsoultan/gateon/internal/middleware/traffic"
	"github.com/gsoultan/gateon/internal/middleware/transform"
	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/internal/security/reputation"
	"github.com/gsoultan/gateon/internal/security/yara"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Factory creates a Middleware from a configuration.
type Factory struct {
	redisClient redis.Client
	globalStore config.GlobalConfigStore
	ebpfManager ebpf.Manager
	reputation  *reputation.IPReputationStore
	dataDir     string
	routeType   string // trusted route type (e.g. "grpc"); empty = treat as plain HTTP
}

func NewFactory(redisClient redis.Client, globalStore config.GlobalConfigStore, ebpfManager ebpf.Manager, reputation *reputation.IPReputationStore, dataDir string) *Factory {
	return &Factory{redisClient: redisClient, globalStore: globalStore, ebpfManager: ebpfManager, reputation: reputation, dataDir: dataDir}
}

// SetRouteType records the trusted route type for the route this factory builds
// middlewares for. It controls gRPC-specific WAF relaxations, which must be keyed
// on the operator-configured route type rather than a spoofable request header.
// A factory is created per route in ApplyRouteMiddlewares and used synchronously,
// so this is safe to set before building the chain.
func (f *Factory) SetRouteType(t string) {
	f.routeType = t
}

// IsGRPCRoute reports whether this factory builds for a gRPC-typed route.
// securityDeps gathers what the security middlewares used to read off the
// factory directly. Built here rather than at each call site so the field list
// exists once: the WAF needs four of them and a mistake in one literal would be
// invisible.
func (f *Factory) securityDeps() security.Deps {
	return security.Deps{
		GlobalStore: f.globalStore,
		EbpfManager: f.ebpfManager,
		Reputation:  f.reputation,
		DataDir:     f.dataDir,
		RouteType:   f.routeType,
	}
}

// CreateGlobalWAF stays a factory method because the router calls it, and the
// router has no business assembling the security package's dependencies.
func (f *Factory) CreateGlobalWAF() (kind.Middleware, error) {
	return waf.NewGlobalWAF(f.securityDeps())
}

func (f *Factory) IsGRPCRoute() bool {
	return strings.EqualFold(strings.TrimSpace(f.routeType), "grpc")
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
		if _, ok := cfg[kind.RouteIDKey]; !ok {
			cfg[kind.RouteIDKey] = routeID
		}
	}

	switch m.Type {
	case "ratelimit":
		return traffic.NewRateLimit(cfg, f.redisClient, f.ebpfManager)
	case "auth":
		return f.createAuth(cfg)
	case "headers":
		return transform.NewHeaders(cfg)
	case "forwardedheaders":
		return ForwardedHeaders(ForwardedHeadersConfig{
			Proto:              cfg["proto"],
			TrustForwardHeader: parseBoolStrict(cfg["trust_forward_header"], false),
		}), nil
	case "rewrite":
		return transform.NewRewrite(cfg)
	case "addprefix":
		return transform.AddPrefix(cfg["prefix"]), nil
	case "stripprefix":
		prefixes := strings.Split(cfg["prefixes"], ",")
		return transform.StripPrefix(prefixes), nil
	case "stripprefixregex":
		return transform.StripPrefixRegex(cfg["regex"])
	case "replacepath":
		return transform.ReplacePath(cfg["path"]), nil
	case "replacepathregex":
		return transform.ReplacePathRegex(cfg["pattern"], cfg["replacement"])
	case "accesslog":
		return AccessLog(cmp.Or(cfg["route"], cfg[kind.RouteIDKey])), nil
	case "metrics":
		return Metrics(cmp.Or(cfg["route"], cfg[kind.RouteIDKey])), nil
	case "compress":
		return traffic.NewCompress(cfg)
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
		attempts, err := kind.ParseIntStrict(cfg["attempts"], 0)
		if err != nil {
			return nil, kind.CfgError("attempts", cfg["attempts"], err)
		}
		return traffic.Retry(traffic.RetryConfig{Attempts: attempts}), nil
	case "cors":
		return transform.NewCORS(cfg)
	case "grpcweb":
		return f.createGRPCWeb(cfg)
	case "ipfilter":
		return security.NewIPFilter(cfg)
	case "request_id":
		return RequestID(), nil
	case "cache":
		return traffic.NewCache(cfg, f.redisClient)
	case "inflightreq":
		return traffic.NewInflightReq(cfg)
	case "buffering":
		return traffic.NewBuffering(cfg)
	case "forwardauth":
		return f.createForwardAuth(cfg)
	case "waf":
		return waf.NewWAF(cfg, f.securityDeps())
	case "oidc":
		return f.createOIDCProxy(cfg)
	case "graphql_firewall":
		return security.NewGraphQLFirewall(cfg)
	case "bot_management":
		return security.NewBotManagement(cfg, f.securityDeps())
	case "xss_recognition":
		return security.XSSRecognition(routeID), nil
	case "sqli_recognition":
		return security.SQLiRecognition(routeID), nil
	case "threat_recognition":
		return security.ThreatRecognition(routeID), nil
	case "schema_validation":
		return security.SchemaValidation(security.SchemaValidationConfig{Schema: cfg["schema"]})
	case "honeypot":
		return security.NewHoneypot(cfg), nil
	case "turnstile":
		return security.NewTurnstile(cfg)
	case "geoip":
		return security.NewGeoIP(cfg)
	case "hmac":
		return f.createHMAC(cfg)
	case "deception":
		return security.Deception(security.DeceptionConfig{
			HoneypotPaths:        kind.ParseListStrict(cmp.Or(cfg["honeypot_paths"], cfg["paths"])),
			InjectInvisibleLinks: parseBoolStrict(cmp.Or(cfg["inject_invisible_links"], "true"), true),
			InvisibleLinkPaths:   kind.ParseListStrict(cmp.Or(cfg["invisible_link_paths"], cfg["honey_links"])),
			HoneyForms:           kind.ParseListStrict(cfg["honey_forms"]),
			RouteID:              routeID,
			EnableTrollResponse:  parseBoolStrict(cfg["enable_troll_response"], false),
			CanaryHeader:         cfg["canary_header"],
			CanaryToken:          cfg["canary_token"],
		}), nil
	case "tarpit":
		baseDelay, err := kind.ParseDurationStrict(cfg["base_delay"], 0)
		if err != nil {
			return nil, kind.CfgError("base_delay", cfg["base_delay"], err)
		}
		maxDelay, err := kind.ParseDurationStrict(cfg["max_delay"], 0)
		if err != nil {
			return nil, kind.CfgError("max_delay", cfg["max_delay"], err)
		}
		threshold, err := kind.ParseFloatStrict(cfg["threshold"], 0)
		if err != nil {
			return nil, kind.CfgError("threshold", cfg["threshold"], err)
		}
		return security.Tarpit(baseDelay, maxDelay, threshold), nil
	case "entropy":
		threshold, err := kind.ParseFloatStrict(cfg["threshold"], 0)
		if err != nil {
			return nil, kind.CfgError("threshold", cfg["threshold"], err)
		}
		return security.Entropy(threshold, routeID), nil
	case "pow":
		difficulty, err := kind.ParseIntStrict(cfg["difficulty"], 4)
		if err != nil {
			return nil, kind.CfgError("difficulty", cfg["difficulty"], err)
		}
		if difficulty == 0 {
			difficulty = 4
		}
		threshold, err := kind.ParseFloatStrict(cfg["threshold"], 20.0)
		if err != nil {
			return nil, kind.CfgError("threshold", cfg["threshold"], err)
		}
		if threshold == 0 {
			threshold = 20.0
		}
		return security.Pow(difficulty, threshold, cfg["secret"], routeID), nil
	case "policy":
		return security.NewPolicy(cfg)
	case "xfcc":
		return transform.NewXFCC(cfg)
	case "transform":
		return transform.BodyTransform(transform.BodyTransformConfig{
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
		return identity.TlsBinding(cookieName), nil
	case "security_headers":
		return SecurityHeaders(SecurityHeadersConfig{Preset: cfg["preset"]}), nil
	case "circuit_breaker":
		errorThreshold, err := kind.ParseFloatStrict(cfg["error_threshold"], 0)
		if err != nil {
			return nil, kind.CfgError("error_threshold", cfg["error_threshold"], err)
		}
		minRequestsInt, err := kind.ParseIntStrict(cfg["min_requests"], 0)
		if err != nil {
			return nil, kind.CfgError("min_requests", cfg["min_requests"], err)
		}
		minRequests := int64(minRequestsInt)
		windowSize, err := kind.ParseDurationStrict(cfg["window_size"], 0)
		if err != nil {
			return nil, kind.CfgError("window_size", cfg["window_size"], err)
		}
		sleepWindow, err := kind.ParseDurationStrict(cfg["sleep_window"], 0)
		if err != nil {
			return nil, kind.CfgError("sleep_window", cfg["sleep_window"], err)
		}
		return CircuitBreaker(CircuitBreakerConfig{
			ErrorThreshold: errorThreshold,
			MinRequests:    minRequests,
			WindowSize:     windowSize,
			SleepWindow:    sleepWindow,
			RouteID:        routeID,
		}), nil
	case "wasm":
		return transform.Wasm(context.Background(), m.WasmBlob)
	default:
		return nil, fmt.Errorf("unknown middleware type: %s", m.Type)
	}
}

func (f *Factory) createGRPCWeb(cfg map[string]string) (Middleware, error) {
	origins := kind.ParseListStrict(cfg["allowed_origins"])
	allowCredentials := parseBoolStrict(cfg["allow_credentials"], false)
	maxAge, err := kind.ParseIntStrict(cfg["max_age"], 0)
	if err != nil {
		return nil, kind.CfgError("max_age", cfg["max_age"], err)
	}

	corsCfg := transform.CORSConfig{
		AllowedOrigins:   origins,
		AllowCredentials: allowCredentials,
		MaxAge:           maxAge,
	}

	// For grpcweb, we use the "grpc-web" preset as a starting point if no preset is specified
	// but only if it's explicitly configured or if origins are provided.
	if cfg["preset"] == "" && len(origins) > 0 {
		cfg["preset"] = "grpc-web"
	}

	corsCfg = transform.ApplyCORSPreset(cfg, corsCfg)

	// If after applying presets and config we still have no origins, return default permissive
	if len(corsCfg.AllowedOrigins) == 0 && cfg["preset"] == "" {
		return transform.GRPCWeb(), nil
	}

	return transform.GRPCWeb(corsCfg), nil
}

func (f *Factory) createOIDCProxy(cfg map[string]string) (Middleware, error) {
	scopes := kind.ParseListStrict(cfg["scopes"])
	return OIDCProxy(OIDCProxyConfig{
		Issuer:       cfg["issuer"],
		ClientID:     cfg["client_id"],
		ClientSecret: cfg["client_secret"],
		RedirectURL:  cfg["redirect_url"],
		Scopes:       scopes,
		RouteID:      cfg[kind.RouteIDKey],
	})
}

func (f *Factory) createFileSecurity(cfg map[string]string) (Middleware, error) {
	maxFileSizeInt, err := kind.ParseIntStrict(cfg["max_file_size"], 0)
	if err != nil {
		return nil, kind.CfgError("max_file_size", cfg["max_file_size"], err)
	}
	maxFileSize := int64(maxFileSizeInt)
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

	scanTimeout, err := kind.ParseDurationStrict(cfg["scan_timeout"], 0)
	if err != nil {
		return nil, kind.CfgError("scan_timeout", cfg["scan_timeout"], err)
	}
	maxConcurrentScans, err := kind.ParseIntStrict(cfg["max_concurrent_scans"], 0)
	if err != nil {
		return nil, kind.CfgError("max_concurrent_scans", cfg["max_concurrent_scans"], err)
	}
	maxScanBytesInt, err := kind.ParseIntStrict(cfg["max_scan_bytes"], 0)
	if err != nil {
		return nil, kind.CfgError("max_scan_bytes", cfg["max_scan_bytes"], err)
	}
	maxScanBytes := int64(maxScanBytesInt)

	return security.FileSecurity(security.FileSecurityConfig{
		EnableClamAV:           parseBoolStrict(cfg["enable_clamav"], false),
		ClamAVAddr:             clamavAddr,
		BlockedMimeTypes:       kind.ParseListStrict(cfg["blocked_mime_types"]),
		AllowedMimeTypes:       kind.ParseListStrict(cfg["allowed_mime_types"]),
		MaxFileSize:            maxFileSize,
		ScanTimeout:            scanTimeout,
		FailOpen:               parseBoolStrict(cfg["fail_open"], false),
		MaxConcurrentScans:     maxConcurrentScans,
		MaxScanBytes:           maxScanBytes,
		EnableSignatureScan:    parseBoolStrict(cfg["enable_signature_scan"], true),
		SignatureRulesPath:     cfg["signature_rules_path"],
		SignatureBlockSeverity: yara.Severity(cfg["signature_block_severity"]),
		RouteID:                cfg[kind.RouteIDKey],
	}), nil
}
