// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package router provides request routing functionality based on Rules and EntryPoints.
package router

import (
	"cmp"
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"sync"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/middleware/security"
	"github.com/gsoultan/gateon/internal/middleware/security/challenge"
	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/middleware/transform"
	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/router/rule"
	"github.com/gsoultan/gateon/internal/security/reputation"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

var (
	ruleCache sync.Map // map[string]Matcher
)

// GetMatcher returns the matcher for a rule, parsing it on first use. A rule
// that does not parse is logged once, when it is first seen, and matches no
// request: the route save path refuses such a rule, so one reaches here only
// from a store written before that check or by hand (ADR 0043). It used to
// parse to a matcher with no condition, which matches every request and took
// the entrypoint's traffic from the routes that did describe it.
func GetMatcher(src string) Matcher {
	if v, ok := ruleCache.Load(src); ok {
		if m, isMatcher := v.(Matcher); isMatcher {
			return m
		}
	}
	m, err := compileRule(src)
	actual, loaded := ruleCache.LoadOrStore(src, m)
	if !loaded && err != nil && strings.TrimSpace(src) != "" {
		logger.L.LogError("route rule does not parse; every route with this rule matches no request until it is fixed",
			"rule", truncateRule(src), "error", err)
	}
	if loaded {
		if am, isMatcher := actual.(Matcher); isMatcher {
			return am
		}
	}
	return m
}

// Matcher is a route's parsed rule.
type Matcher struct {
	// expr is nil when the rule does not parse; such a matcher matches nothing.
	expr *rule.Expr
}

// compileRule parses a rule. An unreadable rule is a Matcher that matches
// nothing, with the reason.
func compileRule(src string) (Matcher, error) {
	e, err := rule.Parse(src)
	if err != nil {
		return Matcher{}, err
	}
	return Matcher{expr: e}, nil
}

func parseRule(src string) Matcher {
	m, _ := compileRule(src)
	return m
}

// truncateRule bounds a rule for a log line; a rule is as long as the API body
// allows.
func truncateRule(src string) string {
	const limit = 256
	if len(src) <= limit {
		return src
	}
	return src[:limit] + "..."
}

// Match reports whether r satisfies the rule. A rule that did not parse
// matches nothing.
func (m Matcher) Match(r *http.Request) bool {
	if m.expr == nil {
		return false
	}
	return m.expr.Match(r, requestHost(r))
}

// requestHost is the request's host without its port, as the entrypoint
// resolved it when it did.
func requestHost(r *http.Request) string {
	if rs := request.GetRequestState(r); rs != nil && rs.StrippedHost != "" {
		return rs.StrippedHost
	}
	return httputil.StripPort(r.Host)
}

// HasHost reports whether the rule holds every request it matches to a host.
func (m Matcher) HasHost() bool {
	return m.expr != nil && m.expr.HasHost()
}

// RequiredHeaders are the headers every match must carry, by canonical name.
func (m Matcher) RequiredHeaders() map[string]string {
	if m.expr == nil {
		return nil
	}
	return m.expr.RequiredHeaders()
}

// HostFromRule returns the host part of a rule if it contains Host(`...`), otherwise "".
// Used by SNI to select certificates for multi-host TLS.
func HostFromRule(src string) string {
	if m := GetMatcher(src); m.expr != nil {
		return m.expr.Host()
	}
	return ""
}

// RouteHasHostRule returns true if the rule explicitly matches against a host
// (via Host() or HostRegexp()). This is used to prioritize host-specific routes
// over generic management endpoints when they overlap (e.g. /v1).
func RouteHasHostRule(rule string) bool {
	return GetMatcher(rule).HasHost()
}

// RouteHostIsExact returns true if routeHost is an exact host (e.g. api.example.com),
// false if it is a wildcard (e.g. *.example.com). Used by SNI to prefer exact matches.
func RouteHostIsExact(routeHost string) bool {
	return config.RouteHostIsExact(routeHost)
}

// HostMatches checks if the request host matches the route's host specification,
// supporting wildcards like *.example.com.
func HostMatches(rh string, qh string) bool {
	return config.HostMatches(rh, qh)
}

// SelectRoute finds the best matching route for the given request using a high-performance Radix Tree (PathTrie).
func SelectRoute(r *http.Request, store config.RouteStore) *gateonv1.Route {
	// Resolve dot segments before anything decides which route this is.
	//
	// Done here rather than at each caller because this is where every route
	// decision converges, and a guarantee that holds only while both callers
	// remember to normalise first is the kind that breaks quietly. Mutating the
	// request is deliberate: the proxy forwards r.URL.Path, so resolving it here
	// is also what keeps the route the gateway chose and the path the backend
	// receives from disagreeing. r.RequestURI keeps the original, so the WAF and
	// the access log still see what the client actually sent.
	//
	// A path some backends resolve differently from this router ("..;", a
	// backslash) selects no route at all (DP-F8): there is no route that is
	// right for it. The base handler refuses it with 400 before getting here;
	// this is the backstop for any caller that does not.
	if AmbiguousPath(r.URL.Path) {
		return nil
	}
	if clean := NormalizePath(r.URL.Path); clean != r.URL.Path {
		r.URL.Path = clean
		r.URL.RawPath = ""
	}

	host := ""
	if rs := request.GetRequestState(r); rs != nil && rs.StrippedHost != "" {
		host = rs.StrippedHost
	} else {
		host = httputil.StripPort(r.Host)
	}

	// 1. Try host-specific routes first (O(log N) lookup in Trie + small O(M) regex scan)
	trie, regexes := store.GetTrieByHost(host)
	if trie != nil || len(regexes) > 0 {
		if rt := SelectRouteFromTrie(r, trie, regexes); rt != nil {
			return rt
		}
	}

	// 2. Fallback to wildcard routes (wildcards, Path-only rules, etc.)
	trie, regexes = store.GetWildcardTrie()
	if trie != nil || len(regexes) > 0 {
		return SelectRouteFromTrie(r, trie, regexes)
	}

	return nil
}

// SelectRouteFromTrie narrows down candidates using the PathTrie, adds regex-based routes,
// and then performs a final prioritized match check.
func SelectRouteFromTrie(r *http.Request, trie *config.PathTrie, regexes []*gateonv1.Route) *gateonv1.Route {
	var candidates []*gateonv1.Route
	if trie != nil {
		candidates = trie.Lookup(r.URL.Path)
	}

	if len(regexes) == 0 {
		return SelectRouteFromSlice(r, candidates)
	}

	if len(candidates) == 0 {
		return SelectRouteFromSlice(r, regexes)
	}

	// If we have both, we must merge and sort them because regexes might have higher priority.
	// We optimize for the common case where one of them is empty.
	all := make([]*gateonv1.Route, 0, len(candidates)+len(regexes))
	all = append(all, candidates...)
	all = append(all, regexes...)

	slices.SortFunc(all, func(a, b *gateonv1.Route) int {
		if a.Priority != b.Priority {
			return cmp.Compare(b.Priority, a.Priority)
		}
		if len(a.Rule) != len(b.Rule) {
			return cmp.Compare(len(b.Rule), len(a.Rule))
		}
		return strings.Compare(a.Id, b.Id)
	})

	return SelectRouteFromSlice(r, all)
}

// SelectRouteFromSlice finds the best matching route from a provided slice of routes.
// The input slice is expected to be sorted by Priority DESC and Rule specificity DESC,
// allowing us to short-circuit and return the first match (O(1) on average).
func SelectRouteFromSlice(r *http.Request, routes []*gateonv1.Route) *gateonv1.Route {
	epID := ""
	if rs := request.GetRequestState(r); rs != nil {
		epID = rs.EntryPointID
	} else if val, ok := r.Context().Value(middleware.EntryPointIDContextKey).(string); ok {
		epID = val
	}

	for _, rt := range routes {
		if rt.Disabled {
			continue
		}
		// 1. Filter by EntryPoints if specified
		if len(rt.Entrypoints) > 0 {
			matchEP := false
			for _, e := range rt.Entrypoints {
				if e == epID {
					matchEP = true
					break
				}
			}
			if !matchEP {
				continue
			}
		}

		// 2. Filter by Rule
		if rt.Rule == "" {
			continue
		}

		m := GetMatcher(rt.Rule)
		if m.Match(r) {
			// Since routes are pre-sorted by Priority and Rule length,
			// the first match is guaranteed to be the "best" one.
			return rt
		}
	}
	return nil
}

// RouteHasMiddlewareType returns true if the route has any middleware of the given type.
func RouteHasMiddlewareType(ctx context.Context, rt *gateonv1.Route, mwStore config.MiddlewareStore, mwType string) bool {
	if mwStore == nil || mwType == "" {
		return false
	}
	for _, mid := range rt.Middlewares {
		mid = strings.TrimSpace(mid)
		if mid == "" {
			continue
		}
		if mwConf, ok := mwStore.Get(ctx, mid); ok && mwConf != nil && strings.EqualFold(mwConf.Type, mwType) {
			return true
		}
	}
	return false
}

// RouteReplacesBackendCORS reports whether a route answers CORS itself, so
// the proxy strips the backend's CORS headers rather than send two policies:
// a grpcweb middleware, or a cors middleware that is not the backend preset.
// A backend-preset route leaves CORS to the backend and must not strip it.
func RouteReplacesBackendCORS(ctx context.Context, rt *gateonv1.Route, mwStore config.MiddlewareStore) bool {
	if mwStore == nil {
		return false
	}
	for _, mid := range rt.Middlewares {
		mwConf, ok := mwStore.Get(ctx, strings.TrimSpace(mid))
		if !ok || mwConf == nil {
			continue
		}
		switch strings.ToLower(mwConf.Type) {
		case "grpcweb":
			return true
		case "cors":
			if !transform.IsBackendCORS(mwConf.Config) {
				return true
			}
		}
	}
	return false
}

// RouteLabel is the name a route's middlewares, metrics and per-route state
// are keyed by: its name, or its ID when it has none.
func RouteLabel(rt *gateonv1.Route) string {
	return cmp.Or(rt.Name, rt.Id)
}

// managementSessionsSource is a route's final handler that knows the
// management plane's session check: the proxy handler (ADR 0041, 0051).
type managementSessionsSource interface {
	ManagementSessions() middleware.TokenVerifier
}

// ApplyRouteMiddlewares wraps the handler with infrastructure middlewares and user-defined middlewares from the store.
func ApplyRouteMiddlewares(h http.Handler, rt *gateonv1.Route, redisClient redis.Client, mwStore config.MiddlewareStore, globalStore config.GlobalConfigStore, ebpfManager ebpf.Manager, reputation *reputation.IPReputationStore) http.Handler {
	var chain []middleware.Middleware
	mwFactory := middleware.NewFactory(redisClient, globalStore, ebpfManager, reputation, ".")
	// Record the trusted route type so the WAF applies gRPC transport relaxations
	// only to operator-declared gRPC routes, not based on a spoofable request header.
	mwFactory.SetRouteType(rt.Type)
	// Per-route state is kept under the ID, which is unique; the label below
	// is only what a person reads.
	mwFactory.SetRouteKey(rt.Id)
	// The management plane's session check, from the proxy handler that has
	// it, for the middlewares that send credentials to another server.
	if src, ok := h.(managementSessionsSource); ok {
		mwFactory.SetManagementSessions(src.ManagementSessions())
	}

	routeLabel := RouteLabel(rt)
	ctx := context.Background()

	// 1. Infrastructure Middlewares (Recovery, Logging & Monitoring)
	// Recovery is outer-most to catch panics in logging or metrics.
	chain = append(chain,
		middleware.Recovery(),
		middleware.AccessLog(routeLabel),
		middleware.MetricsWithService(routeLabel, rt.ServiceId),
	)
	// Ahead of every middleware that could set them: the headers a service
	// chooses its backend client certificate by are the gateway's alone.
	if guard := clientIdentityGuard(h); guard != nil {
		chain = append(chain, guard)
	}

	// 2. Identify and resolve CORS/gRPC-Web early.
	// We MUST place these outer to security blockers (IP shunning, WAF, etc.)
	// to ensure that even blocked requests include the necessary CORS headers
	// and that preflight (OPTIONS) requests are handled correctly without
	// triggering false security alerts.
	var userMiddlewares []middleware.Middleware
	var corsMiddleware middleware.Middleware
	hasCORS := false
	// hasWAF records whether this route attached its own "waf" middleware and it
	// built successfully. It gates the gateway-wide WAF below: a route with its
	// own WAF is an explicit override and must not also run the global one.
	// Setting it only on a successful Create is deliberate — if the per-route WAF
	// fails to build, hasWAF stays false and the global WAF still covers the
	// route, so a misconfigured override fails safe rather than open.
	hasWAF := false

	// Security middlewares that could not be built. A route with any of these
	// serves a refusal rather than a chain missing a control it was configured
	// to have.
	var missingSecurity []string

	if mwStore != nil {
		for _, mid := range rt.Middlewares {
			mid = strings.TrimSpace(mid)
			if mid == "" {
				continue
			}
			mwConf, found := mwStore.Get(ctx, mid)
			if !found || mwConf == nil {
				// A route naming a middleware that is not in the store used to
				// skip silently, so a renamed or deleted middleware removed
				// whatever it enforced with nothing to notice. Treated as a
				// build failure of unknown type, which fails closed.
				logger.L.LogError("route names a middleware that does not exist; "+
					"the route will refuse requests until it is fixed",
					"route", routeLabel, "middleware", mid)
				missingSecurity = append(missingSecurity, mid)
				continue
			}

			mw, err := mwFactory.Create(mwConf, routeLabel)
			if err != nil {
				// Previously a bare `continue`: the middleware vanished from
				// the chain, nothing was logged, and the chain is cached until
				// invalidated -- so a transient failure was baked in. An oidc
				// middleware whose IdP discovery failed left the route serving
				// with no authentication while the dashboard still listed it.
				if isSecurityMiddleware(mwConf.Type) {
					logger.L.LogError("security middleware failed to build; the route "+
						"will refuse requests rather than serve without it",
						"route", routeLabel, "middleware", mid,
						"type", mwConf.Type, "error", err)
					missingSecurity = append(missingSecurity, mid)
				} else {
					logger.L.LogWarn("middleware failed to build; the route will "+
						"serve without it",
						"route", routeLabel, "middleware", mid,
						"type", mwConf.Type, "error", err)
				}
				continue
			}
			{
				if strings.EqualFold(mwConf.Type, "cors") || strings.EqualFold(mwConf.Type, "grpcweb") {
					if !hasCORS {
						corsMiddleware = mw
						hasCORS = true
					}
				} else {
					if strings.EqualFold(mwConf.Type, "waf") {
						hasWAF = true
					}
					userMiddlewares = append(userMiddlewares, mw)
				}
			}
		}
	}

	// A route configured with a security middleware that could not be built
	// serves a refusal, not a chain missing the control.
	//
	// The alternative is what this code used to do: drop it and serve anyway.
	// That is worse in the direction that matters -- an oidc middleware whose
	// IdP discovery failed left the route publicly readable while the
	// dashboard still showed authentication attached, and route chains are
	// cached until invalidated, so a blip at build time persisted.
	//
	// Cosmetic middlewares are exempt and only warn: a route that loses a
	// header rewrite renders slightly wrong, which is not worth an outage.
	if len(missingSecurity) > 0 {
		return newRefusedChain(routeLabel, missingSecurity)
	}

	if hasCORS {
		// Publish the matched route before CORS runs so a CORS violation is
		// reported against the real route id. RouteName is deliberately left
		// untouched here: the security middlewares below key their metrics-skip
		// behavior off an unset name.
		chain = append(chain, withMatchedRoute(rt), corsMiddleware)
	} else {
		// No policy of the route's own: the backend's, or the permissive
		// default where the backend sends none. Outer to the security
		// middlewares for the same reason a route's own policy is, so a
		// refusal made on this route stays readable by the page that caused it.
		chain = append(chain, transform.DefaultCORS())
	}

	// 3. Infrastructure Blockers & Lifecycle (inner to CORS)
	chain = append(chain,
		identity.IPMitigation(),
		identity.UserMitigation(),
		identity.ReputationBlocker(routeLabel),
		func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if rs := request.GetRequestState(r); rs != nil {
					rs.TMiddlewareStart = time.Now().UnixNano()
				}
				next.ServeHTTP(w, r)
				if rs := request.GetRequestState(r); rs != nil {
					rs.TMiddlewareEnd = time.Now().UnixNano()
				}
			})
		},
		middleware.Debugger(globalStore),
	)

	// 4. Advanced Security Middlewares
	if globalStore != nil {
		if gcfg := globalStore.Get(context.Background()); gcfg != nil && gcfg.SecurityAdvanced != nil {
			adv := gcfg.SecurityAdvanced
			// Tarpit should be early to slow down attackers before processing
			if adv.Tarpit != nil && adv.Tarpit.Enabled {
				chain = append(chain, security.Tarpit(
					time.Duration(adv.Tarpit.DelayBaseMs)*time.Millisecond,
					time.Duration(adv.Tarpit.DelayMaxMs)*time.Millisecond,
					adv.Tarpit.ScoreThreshold,
				))
			}
			// PoW challenge. Refuse to install a forgeable one: a challenge keyed
			// on an empty or published secret can be solved offline, so running it
			// would leave the operator believing the route was defended when it was
			// not. Declining loudly is the honest failure mode.
			if adv.Pow != nil && adv.Pow.Enabled {
				if config.IsPlaceholderPowSecret(adv.Pow.Secret) {
					logger.L.LogError("proof-of-work enabled with an empty or placeholder secret; "+
						"refusing to install a forgeable challenge - set a unique secret to enable it",
						"route", routeLabel)
				} else {
					chain = append(chain, challenge.Pow(int(adv.Pow.Difficulty), adv.Pow.ScoreThreshold, adv.Pow.Secret, routeLabel))
				}
			}
			// Deception
			if adv.Deception != nil && adv.Deception.Enabled {
				chain = append(chain, security.Deception(security.DeceptionConfig{
					HoneypotPaths:        adv.Deception.HoneypotPaths,
					InjectInvisibleLinks: adv.Deception.InjectInvisibleLinks,
					InvisibleLinkPaths:   adv.Deception.InvisibleLinkPaths,
					HoneyForms:           adv.Deception.HoneyForms,
					CanaryHeader:         adv.Deception.CanaryHeader,
					CanaryToken:          adv.Deception.CanaryToken,
					EnableTrollResponse:  adv.Deception.EnableTrollResponse,
					RouteID:              routeLabel,
				}))
			}
			// Entropy
			if adv.Entropy != nil && adv.Entropy.Enabled {
				chain = append(chain, security.Entropy(adv.Entropy.Threshold, routeLabel))
			}
			// The global TLS Session Binding switch is retired (ADR 0046).
			if adv.TlsBinding.GetEnabled() {
				warnGlobalTLSBindingRetired()
			}
		}
	}

	// Set the route name once for the user middlewares and the inner proxy
	// handler, rather than re-allocating a context value on every middleware on
	// every request. Placed after the infrastructure/security middlewares so it
	// does not alter their metrics-skip behavior, which keys off an unset name.
	chain = append(chain, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rs := middleware.GetRequestState(r); rs != nil {
				rs.RouteName = routeLabel
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), middleware.RouteNameContextKey, routeLabel)))
		})
	})

	// 5. User-defined Middlewares (already resolved during CORS identification)
	chain = append(chain, userMiddlewares...)

	// Global WAF: when enabled in the global config, protect every route with the
	// full OWASP CRS (plus malware/ransomware detection) without requiring a
	// per-route "waf" middleware to be attached. Placed after the user-defined
	// middlewares so it runs closer to the proxy: on the response path it sees
	// uncompressed data (running before Gzip) and on the request path it runs
	// after Auth, avoiding inspection of blocked/unauthenticated traffic and
	// preventing interference with high-entropy auth headers.
	//
	// A route that attached its own "waf" middleware is skipped here: that
	// middleware is an explicit override (its own paranoia level, audit-only,
	// DLP, gRPC relaxations) and already ran in userMiddlewares above, so
	// applying the global WAF too would inspect every request twice and record
	// each block under two route ids. One WAF per request: the route's config
	// where present, the global WAF everywhere else.
	if hasWAF {
		logger.L.LogDebug("route has its own WAF middleware; skipping global WAF", "route", routeLabel)
	} else if gwaf, err := mwFactory.CreateGlobalWAF(); err != nil {
		logger.L.LogError("failed to build global WAF middleware", "error", err, "route", routeLabel)
	} else if gwaf != nil {
		chain = append(chain, gwaf)
	}

	// Last in the chain, nearest the proxy: whether a request reached its
	// service is what tells a backend's 401 from the gateway's own refusals.
	chain = append(chain, request.ServiceBoundary)

	if len(chain) > 0 {
		h = middleware.Chain(chain...)(h)
	}

	return h
}

// withMatchedRoute publishes the matched route on the request state so that
// middlewares running before the route name is assigned can still report the
// route they belong to by its identifier.
func withMatchedRoute(rt *gateonv1.Route) middleware.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rs := request.GetRequestState(r); rs != nil && rs.MatchedRoute == nil {
				rs.MatchedRoute = rt
			}
			next.ServeHTTP(w, r)
		})
	}
}

// globalTLSBindingRetired logs, once per process, that the global TLS Session
// Binding switch does nothing (ADR 0046). It applied the tls_binding check to
// every route with no secret to bind with: nothing could issue a binding, so
// over TLS every request carrying the cookie was refused, and over plain HTTP
// nothing happened. Binding needs a shared secret and client certificates,
// which only a per-route tls_binding middleware can carry, so the switch is no
// longer applied -- dropping a refusal that protected nothing -- and enabling
// it is refused at save.
var globalTLSBindingRetired sync.Once

func warnGlobalTLSBindingRetired() {
	globalTLSBindingRetired.Do(func() {
		logger.L.LogWarn("security_advanced.tls_binding is enabled and does nothing: the global TLS Session " +
			"Binding switch is retired; add a tls_binding middleware (with a secret) to the routes that need it, " +
			"on an entrypoint that asks for client certificates, and turn the switch off")
	})
}
