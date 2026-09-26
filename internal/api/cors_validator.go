// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/gsoultan/gateon/internal/middleware/transform"
	"github.com/gsoultan/gateon/internal/router"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// CORS header names the validator reads off the request it is asked about and
// off the response the proxy would send.
const (
	corsRequestOrigin    = "Origin"
	corsRequestMethod    = "Access-Control-Request-Method"
	corsRequestHeaders   = "Access-Control-Request-Headers"
	corsAllowOrigin      = "Access-Control-Allow-Origin"
	corsAllowCredentials = "Access-Control-Allow-Credentials"
	corsExposeHeaders    = "Access-Control-Expose-Headers"
	corsMaxAge           = "Access-Control-Max-Age"
)

func (s *ApiService) ValidateCORS(ctx context.Context, req *gateonv1.ValidateCORSRequest) (*gateonv1.ValidateCORSResponse, error) {
	req.Url = strings.TrimSpace(req.Url)
	req.Origin = strings.TrimSpace(req.Origin)
	req.AuthBearerToken = strings.TrimSpace(req.AuthBearerToken)

	if req.Url == "" {
		return &gateonv1.ValidateCORSResponse{
			IsAllowed: false,
			Message:   "URL is required",
		}, nil
	}

	// 1. Find the matching route
	u, err := url.Parse(req.Url)
	if err != nil {
		return &gateonv1.ValidateCORSResponse{
			IsAllowed:   false,
			Message:     fmt.Sprintf("Invalid URL: %v", err),
			Suggestions: []string{"Ensure the URL is valid and doesn't contain accidental spaces.", "Check if you included the protocol (e.g., http:// or https://)."},
		}, nil
	}

	if u.Scheme == "" {
		return &gateonv1.ValidateCORSResponse{
			IsAllowed:   false,
			Message:     "URL is missing a protocol (e.g., http:// or https://)",
			Suggestions: []string{fmt.Sprintf("Try changing the URL to: https://%s", req.Url)},
		}, nil
	}

	// Create a dummy http.Request for matching.
	//
	// The error is checked rather than discarded: the method is caller-supplied
	// and http.NewRequest rejects anything that is not an HTTP token, returning
	// a nil request. Every line below dereferences it, so discarding the error
	// turned a typo in the dashboard's method box into a wedged request
	// goroutine that never returns.
	dummyReq, err := http.NewRequest(req.Method, req.Url, nil)
	if err != nil {
		return &gateonv1.ValidateCORSResponse{
			IsAllowed:   false,
			Message:     fmt.Sprintf("Invalid request: %v", err),
			Suggestions: []string{"Use a valid HTTP method (e.g., GET, POST, OPTIONS) and a valid URL."},
		}, nil
	}
	// Propagate headers to dummy request for proper route matching (e.g., Access-Control-Request-Method)
	if req.Headers == nil {
		req.Headers = make(map[string]string)
	}
	if req.AuthBearerToken != "" {
		req.Headers["Authorization"] = "Bearer " + req.AuthBearerToken
	}

	for k, v := range req.Headers {
		dummyReq.Header.Set(k, v)
	}
	// Origin is its own field on the request, so it wins over anything the
	// caller also put in Headers; an empty one means "not a CORS request".
	if req.Origin != "" {
		dummyReq.Header.Set(corsRequestOrigin, req.Origin)
	} else {
		dummyReq.Header.Del(corsRequestOrigin)
	}
	// We might need to set Host if it's missing in req.Url but provided in headers
	if dummyReq.Host == "" && req.Headers != nil {
		if host, ok := req.Headers["Host"]; ok {
			dummyReq.Host = host
		}
	}

	routes := s.Routes.List(ctx)
	rt := router.SelectRouteFromSlice(dummyReq, routes)
	if rt == nil {
		// Try to find why it didn't match
		var reasons []string
		for _, r := range routes {
			if r.Disabled {
				continue
			}
			m := router.GetMatcher(r.Rule)

			// Check if host matches
			routeHost := router.HostFromRule(r.Rule)
			hostMatched := router.HostMatches(routeHost, dummyReq.Host)

			// Check if rule matches in general (ignoring entrypoints)
			if m.Match(dummyReq) {
				reasons = append(reasons, fmt.Sprintf("Route '%s' matches the rule but is restricted to entrypoints %v. Your test request has no entrypoint context.", r.Name, r.Entrypoints))
				// If it matches ignoring entrypoints, we can actually use it for CORS validation
				// but let's inform the user.
				rt = r
				break
			} else if hostMatched {
				reasons = append(reasons, fmt.Sprintf("Route '%s' matches the Host but failed other rule parts (Path/Method/Headers). Rule: %s", r.Name, r.Rule))
			} else if routeHost != "" {
				reasons = append(reasons, fmt.Sprintf("Route '%s' Host mismatch: expected '%s', got '%s'", r.Name, routeHost, dummyReq.Host))
			}
		}

		if rt == nil {
			msg := "No route matched the provided URL and Host"
			if len(reasons) > 0 {
				msg += ":\n- " + strings.Join(reasons, "\n- ")
			}
			return &gateonv1.ValidateCORSResponse{
				IsAllowed: false,
				Message:   msg,
			}, nil
		}
	}

	// 2. Find CORS middleware
	var corsMW *gateonv1.Middleware
	for _, mwID := range rt.Middlewares {
		mw, ok := s.Middlewares.Get(ctx, mwID)
		if ok && mw.Type == "cors" {
			corsMW = mw
			break
		}
	}

	if corsMW == nil {
		return &gateonv1.ValidateCORSResponse{
			// No policy of the route's own: the backend's CORS headers go out as
			// sent, and where it sends none the gateway's default allows any
			// origin without credentials (transform.DefaultCORS).
			IsAllowed: true,
			Message: "No CORS middleware on the matched route. The backend's own CORS headers are used as " +
				"sent; where the backend sends none, the gateway allows any origin, without credentials.",
			Checks: []string{"Route matched: " + rt.Name,
				"CORS middleware: none (backend's policy, or the gateway default: any origin, no credentials)"},
			RouteName: rt.Name,
			RouteId:   rt.Id,
		}, nil
	}

	// 3. Ask the real middleware what it would do with this request
	resp, err := s.simulateCORS(dummyReq, corsMW, rt.Name)
	if err == nil && resp != nil {
		resp.RouteId = rt.Id
		resp.Suggestions = append(resp.Suggestions, s.analyzeRoute(ctx, rt, req)...)
	}
	return resp, err
}

func (s *ApiService) analyzeRoute(ctx context.Context, rt *gateonv1.Route, req *gateonv1.ValidateCORSRequest) []string {
	var suggestions []string

	// 1. Analyze Matcher for required headers
	m := router.GetMatcher(rt.Rule)
	for h := range m.RequiredHeaders() {
		if _, ok := req.Headers[h]; !ok {
			suggestions = append(suggestions, fmt.Sprintf("Add header: %s", h))
		}
	}

	// 2. Analyze Middlewares
	for _, mwID := range rt.Middlewares {
		mw, ok := s.Middlewares.Get(ctx, mwID)
		if !ok {
			continue
		}
		switch mw.Type {
		case "auth":
			authType := mw.Config["type"]
			switch authType {
			case "jwt", "paseto", "oidc", "oauth2":
				if _, ok := req.Headers["Authorization"]; !ok && req.AuthBearerToken == "" {
					suggestions = append(suggestions, "Missing Auth: Consider providing a Bearer Token")
				}
			case "apikey":
				header := mw.Config["header"]
				if header == "" {
					header = "X-API-Key"
				}
				if _, ok := req.Headers[header]; !ok {
					suggestions = append(suggestions, fmt.Sprintf("Add header: %s", header))
				}
			case "basic":
				if _, ok := req.Headers["Authorization"]; !ok {
					suggestions = append(suggestions, "Add header: Authorization (Basic)")
				}
			}
		case "forward-auth":
			suggestions = append(suggestions, "Forward Auth active: might need specific headers")
		case "hmac":
			header := mw.Config["header"]
			if header == "" {
				header = "X-Signature"
			}
			if _, ok := req.Headers[header]; !ok {
				suggestions = append(suggestions, fmt.Sprintf("Add header: %s", header))
			}
		}
	}

	// 3. Generic suggestions based on method
	if slices.Contains([]string{"POST", "PUT", "PATCH"}, req.Method) {
		hasContentType := false
		for h := range req.Headers {
			if strings.EqualFold(h, "Content-Type") {
				hasContentType = true
				break
			}
		}
		if !hasContentType {
			suggestions = append(suggestions, "This is a write request (POST/PUT/PATCH). Consider adding a 'Content-Type' header (e.g., 'application/json').")
		}
	}

	return suggestions
}

// simulateCORS answers what the proxy would do with r, by asking the CORS
// middleware built from the same config rather than by re-deriving the policy.
// It used to do the latter, and disagreed with the gateway in eight ways --
// including telling operators that an Authorization preflight was fine on a
// config under which the proxy rejects it.
func (s *ApiService) simulateCORS(r *http.Request, mw *gateonv1.Middleware, routeName string) (*gateonv1.ValidateCORSResponse, error) {
	checks := []string{
		fmt.Sprintf("Route matched: %s", routeName),
		fmt.Sprintf("CORS Middleware: %s", mw.Name),
	}

	if r.Header.Get(corsRequestOrigin) == "" {
		// Not a cross-origin request: the proxy answers with no CORS headers
		// and the browser never applies the policy.
		return &gateonv1.ValidateCORSResponse{
			IsAllowed: true,
			Message:   "No Origin header provided. Request treated as same-origin or non-CORS.",
			Checks:    append(checks, "Origin check: Skipped (no Origin header)"),
		}, nil
	}

	if transform.IsBackendCORS(mw.Config) {
		// The gateway decides nothing here: it neither answers the preflight
		// nor adds or strips a CORS header, so what the browser reads is the
		// backend's answer, which Diagnostics cannot see.
		return &gateonv1.ValidateCORSResponse{
			IsAllowed: true,
			Message: "This route leaves CORS to its backend (preset \"backend\"): the gateway passes the " +
				"request through and the backend's own CORS headers decide.",
			Checks:           append(checks, "CORS policy: the backend's"),
			MiddlewareConfig: mw.Config,
			RouteName:        routeName,
		}, nil
	}

	decision, err := transform.EvaluateCORS(mw.Config, r)
	if err != nil {
		// A middleware config the proxy would refuse to build. Reporting what
		// it "would do" from it is the lie this validator exists to prevent,
		// so the operator gets the key and the value instead.
		return &gateonv1.ValidateCORSResponse{
			IsAllowed:        false,
			Message:          fmt.Sprintf("CORS middleware configuration is invalid: %v", err),
			Checks:           append(checks, "Configuration check: FAILED"),
			MiddlewareConfig: mw.Config,
			RouteName:        routeName,
		}, nil
	}
	outcome := describeCORS(decision, r)
	outcome.suggestions = append(outcome.suggestions, corsCredentialWarnings(decision)...)

	return &gateonv1.ValidateCORSResponse{
		IsAllowed:        decision.Allowed,
		Message:          outcome.message,
		ResponseHeaders:  decision.Headers,
		Checks:           append(checks, outcome.checks...),
		IsPreflight:      decision.IsPreflight,
		MiddlewareConfig: mw.Config,
		RouteName:        routeName,
		Suggestions:      outcome.suggestions,
	}, nil
}

// corsOutcome is the operator-facing half of a decision: which checks ran, why
// the request was refused, and what to change.
type corsOutcome struct {
	checks      []string
	message     string
	suggestions []string
}

func (o *corsOutcome) pass(check string) {
	o.checks = append(o.checks, check)
}

func (o *corsOutcome) deny(check, message, suggestion string) {
	o.checks = append(o.checks, check)
	o.message = message
	o.suggestions = append(o.suggestions, suggestion)
}

// describeCORS narrates a decision in the order rs/cors evaluates it -- origin,
// then method, then requested headers -- and stops at the check that refused,
// because that is where the gateway stops too.
func describeCORS(d transform.CORSDecision, r *http.Request) corsOutcome {
	out := corsOutcome{message: "CORS validation successful"}
	origin := r.Header.Get(corsRequestOrigin)

	if !d.OriginAllowed {
		out.deny(
			fmt.Sprintf("Origin check: FAILED (%s not in %v)", origin, d.Policy.AllowedOrigins),
			fmt.Sprintf("Origin '%s' is not allowed", origin),
			fmt.Sprintf("Add '%s' to Allowed Origins in CORS middleware configuration.", origin))
		return out
	}
	out.pass(fmt.Sprintf("Origin check: Allowed (%s)", origin))

	method := r.Method
	if d.IsPreflight {
		method = r.Header.Get(corsRequestMethod)
	}
	if !d.MethodAllowed {
		out.deny(
			fmt.Sprintf("Method check: FAILED (%s not in %v)", method, d.Policy.AllowedMethods),
			fmt.Sprintf("Method '%s' is not allowed", method),
			fmt.Sprintf("Add '%s' to Allowed Methods in CORS middleware configuration.", method))
		return out
	}
	out.pass(fmt.Sprintf("Method check: Allowed (%s)", method))

	describeCORSHeaders(&out, d, r)
	return out
}

// describeCORSHeaders reports the preflight header check and the extras the
// gateway would answer with. The reported values are read back off the response
// the proxy would send, so they cannot drift from it.
func describeCORSHeaders(out *corsOutcome, d transform.CORSDecision, r *http.Request) {
	requested := r.Header.Get(corsRequestHeaders)
	switch {
	case !d.IsPreflight || requested == "":
		out.pass("Headers check: Skipped (no requested headers)")
	case !d.HeadersAllowed:
		out.deny(
			fmt.Sprintf("Headers check: FAILED (%s not in %v)", requested, d.Policy.AllowedHeaders),
			fmt.Sprintf("Request headers '%s' are not allowed", requested),
			fmt.Sprintf("Add the requested headers (%s) to Allowed Headers in CORS middleware configuration, or set '*'.", requested))
		out.suggestions = append(out.suggestions,
			"Browsers send Access-Control-Request-Headers lowercase, comma-separated and in alphabetical order, and the gateway matches that exact form.")
		return
	default:
		out.pass(fmt.Sprintf("Headers check: Allowed (%s)", requested))
	}

	if d.Headers[corsAllowCredentials] == "true" {
		out.pass("Credentials check: Allowed")
	}
	if exposed := d.Headers[corsExposeHeaders]; exposed != "" {
		out.pass("Exposed Headers: " + exposed)
	}
	if maxAge := d.Headers[corsMaxAge]; maxAge != "" {
		out.pass("Max Age: " + maxAge + " seconds")
	}
}

// corsCredentialWarnings covers the one combination the gateway answers but
// browsers refuse. rs/cors emits `Access-Control-Allow-Origin: *` even with
// credentials enabled, so the verdict has to say allowed to describe the
// gateway honestly -- but the credentialed fetch still fails in the browser,
// which is worth saying out loud. An empty origin list is the same trap: it
// means every origin, which is the wildcard by another name.
func corsCredentialWarnings(d transform.CORSDecision) []string {
	if !d.Policy.AllowCredentials || !slices.Contains(d.Policy.AllowedOrigins, "*") {
		return nil
	}
	return []string{
		"Allowed Origins is '*' while credentials are enabled: the gateway answers 'Access-Control-Allow-Origin: *', which browsers reject for credentialed requests. List the origins explicitly if the client sends cookies or an Authorization header.",
	}
}
