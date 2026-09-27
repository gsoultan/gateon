// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/domain/route"
	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/router"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// entrypointTraceLabelPrefix is how the entrypoint-level metrics middleware
// labels the trace of a request no route matched: "gateon-" and then the
// entrypoint's name, or its id when it has none (entrypointChain in
// internal/server/entrypoint).
const entrypointTraceLabelPrefix = "gateon-"

// unknownServiceName is what a trace records when it knows no service at all.
const unknownServiceName = "unknown"

// The route types a path rule can become.
const (
	routeKindHTTP = "http"
	routeKindGRPC = "grpc"
)

// defaultHoneypotPaths are paths nothing legitimate asks for and every scanner
// does. A request for one is a honeypot_triggered finding, never an unlisted
// route, and the unlisted-route fix refuses to route one.
var defaultHoneypotPaths = []string{"/.env", "/wp-login.php", "/.git/config", "/admin/config.php"}

// UnlistedRouteDetector detects requests to routes not present in the configuration.
type UnlistedRouteDetector struct {
	HoneypotPaths []string
}

// maxFindingSources bounds the client addresses one folded finding lists.
const maxFindingSources = 10

// unlistedKey is what makes two unrouted requests one finding: the same path,
// entrypoint and host. A honeypot finding also keys on the client, because
// each address that springs a trap is its own actor to block.
type unlistedKey struct {
	path, entrypoint, host, source string
}

// foldedFinding is one finding while a pass folds requests into it.
type foldedFinding struct {
	anomaly      *gateonv1.Anomaly
	latest       time.Time
	allMitigated bool
}

// Detect reports one finding per unrouted path, entrypoint and host in the
// pass, carrying how many requests it stands for, the latest one's time and
// client, and up to maxFindingSources distinct clients. It used to report one
// per trace, so a single scanner sweeping a path filled the list with copies.
// Everything it keeps is bounded by the pass's traces.
func (d *UnlistedRouteDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	honeypots := d.HoneypotPaths
	if len(honeypots) == 0 {
		honeypots = defaultHoneypotPaths
	}
	var order []unlistedKey
	found := make(map[unlistedKey]*foldedFinding)
	mitigated := make(map[string]bool)
	for _, tr := range data.Traces {
		// Skip internal Gateon paths and health checks
		if middleware.IsInternalPath(tr.Path) || !unrouted(tr.ServiceName) {
			continue
		}
		honeypot := slices.Contains(honeypots, tr.Path)
		key := unlistedKey{path: tr.Path, entrypoint: unroutedEntrypoint(tr.ServiceName), host: tr.Host}
		if honeypot {
			key.source = tr.SourceIP
		}
		f, ok := found[key]
		if !ok {
			f = &foldedFinding{anomaly: unlistedRouteAnomaly(tr, honeypot), latest: tr.Timestamp, allMitigated: true}
			found[key] = f
			order = append(order, key)
		}
		f.add(tr, isMitigatedOnce(data, mitigated, tr.SourceIP))
	}
	anomalies := make([]*gateonv1.Anomaly, 0, len(order))
	for _, key := range order {
		f := found[key]
		f.anomaly.Mitigated = f.allMitigated
		populateAnomalyGeo(ctx, f.anomaly, f.anomaly.GetSource())
		anomalies = append(anomalies, f.anomaly)
	}
	return anomalies
}

// add folds one more request into the finding: the count, the latest time and
// client, the list of clients, and whether every client is mitigated.
func (f *foldedFinding) add(tr *telemetry.TraceRecord, mitigated bool) {
	a := f.anomaly
	a.Occurrences++
	if tr.Timestamp.After(f.latest) {
		f.latest = tr.Timestamp
		a.Timestamp = tr.Timestamp.Format(time.RFC3339)
		a.Source = tr.SourceIP
	}
	if tr.SourceIP != "" && len(a.SourceIps) < maxFindingSources && !slices.Contains(a.SourceIps, tr.SourceIP) {
		a.SourceIps = append(a.SourceIps, tr.SourceIP)
	}
	f.allMitigated = f.allMitigated && mitigated
}

// isMitigatedOnce answers IsIPMitigated once per address in a pass.
func isMitigatedOnce(data *DiagnosticData, seen map[string]bool, ip string) bool {
	m, ok := seen[ip]
	if !ok {
		m = data.IsIPMitigated(ip)
		seen[ip] = m
	}
	return m
}

// unrouted reports whether a trace's service name says no user route matched:
// empty or "unknown", the entrypoint-level label, or one of the default
// entrypoint ids older traces were labelled with.
func unrouted(serviceName string) bool {
	return serviceName == "" || serviceName == unknownServiceName ||
		strings.HasPrefix(serviceName, entrypointTraceLabelPrefix) ||
		serviceName == routeKindHTTP || serviceName == "https" || serviceName == routeKindGRPC
}

// unroutedEntrypoint returns the entrypoint an unrouted request's trace names,
// as the gateway labels it; "" when the trace does not say.
func unroutedEntrypoint(serviceName string) string {
	if serviceName == unknownServiceName {
		return ""
	}
	return strings.TrimPrefix(serviceName, entrypointTraceLabelPrefix)
}

func unlistedRouteAnomaly(tr *telemetry.TraceRecord, honeypot bool) *gateonv1.Anomaly {
	anomaly := &gateonv1.Anomaly{
		Type:           "unlisted_route",
		Severity:       "medium",
		Description:    fmt.Sprintf("Request to unlisted route/host: %s", tr.Path),
		Timestamp:      tr.Timestamp.Format(time.RFC3339),
		Source:         tr.SourceIP,
		RequestUri:     tr.Path,
		Entrypoint:     unroutedEntrypoint(tr.ServiceName),
		Host:           tr.Host,
		Recommendation: "Verify if this path should be registered in the proxy configuration or blocked.",
		Score:          0.5,
	}
	if honeypot {
		anomaly.Type = "honeypot_triggered"
		anomaly.Severity = "critical"
		anomaly.Description = fmt.Sprintf("Honeypot triggered! Access to trap route: %s", tr.Path)
		anomaly.Recommendation = "This IP is likely a scanner. Block it immediately at the XDP level."
		anomaly.Score = 0.9
	}
	return anomaly
}

// maxUnlistedRoutePathLen bounds the path the fix turns into a rule. The path
// is one a client sent, and a rule is stored, shown and parsed; 1 KiB is well
// past any path an application routes by.
const maxUnlistedRoutePathLen = 1024

// maxRouteHostLen bounds the host written into a rule: a DNS name is at most
// 253 bytes.
const maxRouteHostLen = 253

// routeTarget is the service a route for an unlisted path points at, and why
// that one: the choice is a guess the operator should check. middlewares are
// the ones the routes that chose it all carry, and note says what became of
// them.
type routeTarget struct {
	service     *gateonv1.Service
	why         string
	middlewares []string
	note        string
}

// unlistedRequest is the request an unlisted_route finding describes, once
// its path and entrypoint have been checked: the path as the router sees it,
// the entrypoint it arrived at, and the host it named ("" when not recorded).
type unlistedRequest struct {
	path string
	ep   *gateonv1.EntryPoint
	host string
}

// applyCreateRouteRecommendation turns an unlisted_route finding into a route
// for the path it saw, on the entrypoint it arrived at, pointed at the service
// that already serves that host or entrypoint -- and paused, so nothing is
// exposed until the operator has reviewed it and enabled it in Routes.
//
// It used to answer success and change nothing, and it was handed the
// finding's source, which is the client's address, as the path.
func (s *ApiService) applyCreateRouteRecommendation(ctx context.Context, req *gateonv1.ApplyRecommendationRequest) (*gateonv1.ApplyRecommendationResponse, error) {
	if s.Routes == nil || s.EntryPoints == nil || s.Services == nil {
		return refuseFix("Routes cannot be created here: the route, service or entrypoint store is not available."), nil
	}
	// The Routes API's permission, not only the one this RPC requires: with
	// custom RBAC a role can write diagnostics without being allowed routes.
	if !callerMayWrite(ctx, auth.ResourceRoutes) {
		return refuseFix("Creating a route needs permission to change routes, which your role does not have. Nothing was changed."), nil
	}
	path, problem := unlistedRoutePath(req.GetRequestUri())
	if problem != "" {
		return refuseFix(problem), nil
	}
	ep, problem := s.unlistedRouteEntrypoint(ctx, req.GetEntrypoint())
	if problem != "" {
		return refuseFix(problem), nil
	}
	host, problem := unlistedRouteHost(req.GetHost())
	if problem != "" {
		return refuseFix(problem), nil
	}
	seen := unlistedRequest{path: path, ep: ep, host: host}
	routes := s.Routes.List(ctx)
	if problem := existingRouteFor(routes, seen); problem != "" {
		return refuseFix(problem), nil
	}
	target, problem := s.unlistedRouteTarget(ctx, routes, seen)
	if problem != "" {
		return refuseFix(problem), nil
	}
	return s.createPausedRoute(ctx, seen, target), nil
}

func refuseFix(message string) *gateonv1.ApplyRecommendationResponse {
	return &gateonv1.ApplyRecommendationResponse{Success: false, Message: message}
}

// unlistedRoutePath returns the path a route will be created for, as the
// router will see it, or why there is none.
func unlistedRoutePath(raw string) (string, string) {
	const byHand = " Create the route in the Routes panel if the path is real."
	if raw == "" {
		return "", "The finding does not say which path was requested, so there is nothing to route. Refresh the findings and try again."
	}
	// The router resolves dot segments before it matches, so a rule for the
	// path as sent would never match it.
	p := router.NormalizePath(raw)
	switch {
	case len(p) > maxUnlistedRoutePathLen:
		return "", "The requested path is too long to become a route." + byHand
	case !ruleSafePath(p):
		return "", fmt.Sprintf("The path %q cannot be written as a route rule.", p) + byHand
	case slices.Contains(defaultHoneypotPaths, p):
		return "", fmt.Sprintf("%s is a path only scanners ask for, and a route would expose it. Block the client instead.", p)
	}
	return p, ""
}

// ruleSafePath reports whether p can sit inside Path(`...`) and mean only
// itself. The rule parser ends a value at the first backtick, reads a
// double-quoted form too, and splits the whole rule on "||" before anything
// else, so a path carrying any of them would turn into a different rule.
func ruleSafePath(p string) bool {
	if !strings.HasPrefix(p, "/") || !utf8.ValidString(p) ||
		strings.ContainsAny(p, "`\"") || strings.Contains(p, "||") {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// unlistedRouteHost returns the host the request named -- without its port or
// a trailing root dot, in lower case -- for a Host() condition on the route,
// or "" when the trace recorded none. The Host header is the client's to
// write, so anything that is not plainly a name or an address is refused
// rather than written into a rule.
func unlistedRouteHost(raw string) (string, string) {
	if raw == "" {
		return "", ""
	}
	h := strings.TrimSuffix(strings.ToLower(httputil.StripPort(raw)), ".")
	if h == "" || len(h) > maxRouteHostLen || strings.ContainsFunc(h, notHostRune) {
		return "", fmt.Sprintf("The request's host %q cannot be written as a route rule. Create the route in the Routes panel if it is real.", raw)
	}
	return h, ""
}

// notHostRune reports a rune no host name or address (IPv6 included, its
// brackets already stripped) contains.
func notHostRune(r rune) bool {
	return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '-' && r != '_' && r != ':'
}

// unlistedRouteLabel names the route after what it answers: the host when the
// request named one, and the path. SaveRoute keeps labels unique, so the same
// path on two hosts gets two routes.
func unlistedRouteLabel(seen unlistedRequest) string { return "unlisted " + seen.host + seen.path }

// unlistedRouteRule is the exact path, on the request's host when it named one,
// so that once enabled the route answers that host and nothing else.
func unlistedRouteRule(seen unlistedRequest) string {
	rule := "Path(`" + seen.path + "`)"
	if seen.host == "" {
		return rule
	}
	return "Host(`" + seen.host + "`) && " + rule
}

func entrypointLabel(ep *gateonv1.EntryPoint) string { return cmp.Or(ep.GetName(), ep.GetId()) }

func serviceLabel(svc *gateonv1.Service) string {
	if svc.GetName() == "" || svc.GetName() == svc.GetId() {
		return svc.GetId()
	}
	return fmt.Sprintf("%s (%s)", svc.GetName(), svc.GetId())
}

// unlistedRouteEntrypoint resolves the finding's entrypoint -- an id, or the
// name-or-id label traces carry -- to one that exists and routes by path.
func (s *ApiService) unlistedRouteEntrypoint(ctx context.Context, name string) (*gateonv1.EntryPoint, string) {
	if name == "" {
		return nil, "The finding does not say which entrypoint the request arrived on. Refresh the findings and try again."
	}
	var labelled []*gateonv1.EntryPoint
	for _, ep := range s.EntryPoints.List(ctx) {
		if ep.GetId() == name {
			return routableEntrypoint(ep)
		}
		if entrypointLabel(ep) == name {
			labelled = append(labelled, ep)
		}
	}
	switch len(labelled) {
	case 1:
		return routableEntrypoint(labelled[0])
	case 0:
		return nil, fmt.Sprintf("Entrypoint %s no longer exists, so there is nowhere to put the route.", name)
	default:
		return nil, fmt.Sprintf("More than one entrypoint is called %s, so it is not clear which one the request arrived on.", name)
	}
}

func routableEntrypoint(ep *gateonv1.EntryPoint) (*gateonv1.EntryPoint, string) {
	switch ep.GetType() {
	case gateonv1.EntryPoint_TCP, gateonv1.EntryPoint_UDP:
		return nil, fmt.Sprintf("Entrypoint %s carries %s traffic, which is not routed by path.", entrypointLabel(ep), ep.GetType())
	}
	return ep, ""
}

// routeKind is the type of route a path rule on ep becomes, and so the type of
// route whose service it may borrow.
func routeKind(ep *gateonv1.EntryPoint) string {
	if ep.GetType() == gateonv1.EntryPoint_GRPC {
		return routeKindGRPC
	}
	return routeKindHTTP
}

func kindOf(rt *gateonv1.Route) string {
	switch t := strings.ToLower(rt.GetType()); t {
	case "", routeKindHTTP, "graphql":
		return routeKindHTTP
	default:
		return t
	}
}

// servesEntrypoint reports whether rt is considered on entrypoint epID, as
// router.SelectRouteFromSlice decides it: a route naming no entrypoints is
// considered on all of them.
func servesEntrypoint(rt *gateonv1.Route, epID string) bool {
	return len(rt.GetEntrypoints()) == 0 || slices.Contains(rt.GetEntrypoints(), epID)
}

// existingRouteFor reports a route that already answers for the path on ep:
// the one this fix created before -- found by its label, which SaveRoute keeps
// unique, or by its rule -- paused or not, or an enabled route whose rule
// matches the request today. Applying a finding twice, or one a newer route
// has since answered, says so instead of adding a route.
func existingRouteFor(routes []*gateonv1.Route, seen unlistedRequest) string {
	label, rule := unlistedRouteLabel(seen), unlistedRouteRule(seen)
	probe := &http.Request{Method: http.MethodGet, Host: seen.host, URL: &url.URL{Path: seen.path}, Header: http.Header{}}
	for _, rt := range routes {
		onEP := servesEntrypoint(rt, seen.ep.GetId())
		switch {
		case router.RouteLabel(rt) == label || onEP && rt.GetRule() == rule:
			return fmt.Sprintf("Route %q already exists for %s (%s). Nothing was changed.",
				router.RouteLabel(rt), seen.path, routeState(rt))
		case onEP && !rt.GetDisabled() && rt.GetRule() != "" && router.GetMatcher(rt.GetRule()).Match(probe):
			return fmt.Sprintf("%s on entrypoint %s is already routed by %q. Nothing was created.",
				seen.path, entrypointLabel(seen.ep), router.RouteLabel(rt))
		}
	}
	return ""
}

func routeState(rt *gateonv1.Route) string {
	if rt.GetDisabled() {
		return "paused"
	}
	return "enabled"
}

// unlistedRouteTarget picks the service a route for an unlisted path points
// at: the only service routed for the request's host on the entrypoint or,
// failing that, on the entrypoint; otherwise the one most of those routes use.
func (s *ApiService) unlistedRouteTarget(ctx context.Context, routes []*gateonv1.Route, seen unlistedRequest) (routeTarget, string) {
	pool, scope := routesServing(routes, seen.ep, seen.host)
	if len(pool) == 0 {
		return routeTarget{}, fmt.Sprintf("No service is routed on entrypoint %s yet, so there is no service to point a route at. Create the route in the Routes panel.", entrypointLabel(seen.ep))
	}
	id, uses, others := mostUsedService(pool)
	svc, ok := s.Services.Get(ctx, id)
	if !ok {
		return routeTarget{}, fmt.Sprintf("Service %s, which the routes %s point at, no longer exists. Create the route in the Routes panel.", id, scope)
	}
	why := "the only service routed " + scope
	if others > 0 {
		why = fmt.Sprintf("the most used of the %d services routed %s: %d of those %d routes point at it", others+1, scope, uses, len(pool))
	}
	mws, agree := sharedMiddlewares(pool, id)
	return routeTarget{service: svc, why: why, middlewares: mws, note: middlewareNote(mws, agree)}, ""
}

// sharedMiddlewares returns the middleware list that every route in pool
// pointing at serviceID carries, in its order, and whether they all agree. A
// route for the same service should be guarded as its siblings are -- a WAF,
// authentication, a rate limit -- and a paused route that is enabled without
// them would be the one door to that service left open.
func sharedMiddlewares(pool []*gateonv1.Route, serviceID string) ([]string, bool) {
	var shared []string
	seen := false
	for _, rt := range pool {
		if rt.GetServiceId() != serviceID {
			continue
		}
		if !seen {
			shared, seen = rt.GetMiddlewares(), true
			continue
		}
		if !slices.Equal(shared, rt.GetMiddlewares()) {
			return nil, false
		}
	}
	return slices.Clone(shared), true
}

// middlewareNote says what the new route carries and why.
func middlewareNote(mws []string, agree bool) string {
	switch {
	case !agree:
		return "Those routes carry different middlewares, so it carries none: review its middlewares before enabling it."
	case len(mws) == 0:
		return "Those routes carry no middlewares, and neither does it."
	default:
		return "It carries the middlewares those routes share: " + strings.Join(mws, ", ") + "."
	}
}

// routesServing returns the enabled routes on ep that serve requests like the
// unlisted one, most specific first -- those whose Host() rule names its host,
// then those that serve any host, then every route there -- and says which.
func routesServing(routes []*gateonv1.Route, ep *gateonv1.EntryPoint, host string) ([]*gateonv1.Route, string) {
	kind, h := routeKind(ep), httputil.StripPort(host)
	var forHost, anyHost, all []*gateonv1.Route
	for _, rt := range routes {
		if rt.GetDisabled() || rt.GetServiceId() == "" || kindOf(rt) != kind || !servesEntrypoint(rt, ep.GetId()) {
			continue
		}
		all = append(all, rt)
		ruleHost := router.HostFromRule(rt.GetRule())
		switch {
		case h != "" && ruleHost != "" && router.HostMatches(ruleHost, h):
			forHost = append(forHost, rt)
		case !router.RouteHasHostRule(rt.GetRule()):
			anyHost = append(anyHost, rt)
		}
	}
	switch epl := entrypointLabel(ep); {
	case len(forHost) > 0:
		return forHost, fmt.Sprintf("for host %s on entrypoint %s", h, epl)
	case len(anyHost) > 0:
		return anyHost, "on entrypoint " + epl
	default:
		return all, fmt.Sprintf("on entrypoint %s, where every route names another host", epl)
	}
}

// mostUsedService counts pool's routes per service and returns the service
// most of them point at, how many do, and how many other services appear.
// Ties go to the lowest id, so one configuration always gets one answer.
func mostUsedService(pool []*gateonv1.Route) (string, int, int) {
	uses := make(map[string]int, len(pool))
	for _, rt := range pool {
		uses[rt.GetServiceId()]++
	}
	best, most := "", 0
	for id, n := range uses {
		if n > most || n == most && id < best {
			best, most = id, n
		}
	}
	return best, most, len(uses) - 1
}

// createPausedRoute saves the route through the Routes API's own domain path
// -- its validation, id assignment and unique-label rule -- paused, so it
// matches nothing until the operator enables it.
func (s *ApiService) createPausedRoute(ctx context.Context, seen unlistedRequest, target routeTarget) *gateonv1.ApplyRecommendationResponse {
	rt := &gateonv1.Route{
		Name:        unlistedRouteLabel(seen),
		Type:        routeKind(seen.ep),
		Entrypoints: []string{seen.ep.GetId()},
		Rule:        unlistedRouteRule(seen),
		ServiceId:   target.service.GetId(),
		Middlewares: target.middlewares,
		Disabled:    true,
	}
	if err := s.routeService().SaveRoute(ctx, rt); err != nil {
		if errors.Is(err, route.ErrRouteNameTaken) {
			return refuseFix(fmt.Sprintf("Route %q already exists. Nothing was changed.", rt.Name))
		}
		logger.L.LogError("unlisted-route fix could not save its route", "error", err, "path", seen.path)
		return refuseFix("The route could not be saved; the gateway's log has the reason. Nothing was changed.")
	}
	s.logAudit(ctx, "create", "route", fmt.Sprintf("Created paused route %s (%q) for unlisted path %s", rt.Id, rt.Name, seen.path))
	return &gateonv1.ApplyRecommendationResponse{
		Success: true,
		Message: fmt.Sprintf("Created route %q, paused: %s on entrypoint %s, pointing at service %s, %s. %s%s "+
			"Review it in Routes and enable it there.",
			rt.Name, rt.Rule, entrypointLabel(seen.ep), serviceLabel(target.service), target.why,
			target.note, anyHostNote(seen)),
	}
}

// anyHostNote warns when no host was recorded for the request: the route then
// answers its path for every host the entrypoint serves once it is enabled.
func anyHostNote(seen unlistedRequest) string {
	if seen.host != "" {
		return ""
	}
	return " No host was recorded for the request, so once enabled it answers this path for every host on the entrypoint."
}
