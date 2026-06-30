package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/router"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
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

	// Create a dummy http.Request for matching
	dummyReq, _ := http.NewRequest(req.Method, req.Url, nil)
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
			IsAllowed: true, // If no CORS middleware, browser default applies (usually blocked unless same-origin)
			Message:   "No CORS middleware found on the matched route. Standard browser same-origin policy applies.",
			Checks:    []string{"Route matched: " + rt.Name, "CORS middleware: Not found"},
			RouteName: rt.Name,
			RouteId:   rt.Id,
		}, nil
	}

	// 3. Simulate CORS logic
	resp, err := s.simulateCORS(req, corsMW, rt.Name)
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

func (s *ApiService) simulateCORS(req *gateonv1.ValidateCORSRequest, mw *gateonv1.Middleware, routeName string) (*gateonv1.ValidateCORSResponse, error) {
	config := mw.Config
	allowedOrigins := parseList(config["allowed_origins"])
	allowedMethods := parseList(config["allowed_methods"])
	if len(allowedMethods) == 0 {
		allowedMethods = []string{"GET", "POST", "HEAD"} // rs/cors defaults
	}
	allowedHeaders := parseList(config["allowed_headers"])
	if len(allowedHeaders) == 0 {
		allowedHeaders = []string{"Origin", "Accept", "Content-Type", "Authorization"} // typical defaults
	}
	exposedHeaders := parseList(config["exposed_headers"])
	allowCredentials, _ := strconv.ParseBool(config["allow_credentials"])
	maxAge, _ := strconv.Atoi(config["max_age"])

	checks := []string{
		fmt.Sprintf("Route matched: %s", routeName),
		fmt.Sprintf("CORS Middleware: %s", mw.Name),
	}

	respHeaders := make(map[string]string)
	isAllowed := true
	message := "CORS validation successful"
	var suggestions []string

	origin := req.Origin
	if origin == "" {
		// If no origin, it's a same-origin request or direct access
		return &gateonv1.ValidateCORSResponse{
			IsAllowed: true,
			Message:   "No Origin header provided. Request treated as same-origin or non-CORS.",
			Checks:    append(checks, "Origin check: Skipped (no Origin header)"),
		}, nil
	}

	// Origin check
	if slices.Contains(allowedOrigins, "*") {
		checks = append(checks, "Origin check: Allowed (*) ")
	} else if slices.Contains(allowedOrigins, origin) {
		checks = append(checks, fmt.Sprintf("Origin check: Allowed (%s)", origin))
	} else {
		isAllowed = false
		message = fmt.Sprintf("Origin '%s' is not allowed", origin)
		checks = append(checks, fmt.Sprintf("Origin check: FAILED (%s not in %v)", origin, allowedOrigins))
		suggestions = append(suggestions, fmt.Sprintf("Add '%s' to Allowed Origins in CORS middleware configuration.", origin))
	}

	if isAllowed {
		if slices.Contains(allowedOrigins, "*") {
			respHeaders["Access-Control-Allow-Origin"] = "*"
		} else {
			respHeaders["Access-Control-Allow-Origin"] = origin
			respHeaders["Vary"] = "Origin"
		}

		if allowCredentials {
			if slices.Contains(allowedOrigins, "*") {
				isAllowed = false
				message = "AllowCredentials cannot be used with AllowedOrigins: *"
				checks = append(checks, "Credentials check: FAILED (cannot use credentials with *)")
				suggestions = append(suggestions, "Change Allowed Origins to specific domains (not '*') if you need to use Credentials.")
			} else {
				respHeaders["Access-Control-Allow-Credentials"] = "true"
				checks = append(checks, "Credentials check: Allowed")
			}
		}
	}

	isPreflight := req.Method == http.MethodOptions && req.Headers["Access-Control-Request-Method"] != ""
	if isAllowed && isPreflight {
		// Preflight check
		reqMethod := req.Headers["Access-Control-Request-Method"]
		if slices.Contains(allowedMethods, reqMethod) || slices.Contains(allowedMethods, "*") {
			respHeaders["Access-Control-Allow-Methods"] = reqMethod
			checks = append(checks, fmt.Sprintf("Method check: Allowed (%s)", reqMethod))
		} else {
			isAllowed = false
			message = fmt.Sprintf("Method '%s' is not allowed", reqMethod)
			checks = append(checks, fmt.Sprintf("Method check: FAILED (%s not in %v)", reqMethod, allowedMethods))
			suggestions = append(suggestions, fmt.Sprintf("Add '%s' to Allowed Methods in CORS middleware configuration.", reqMethod))
		}

		if isAllowed {
			reqHeadersStr := req.Headers["Access-Control-Request-Headers"]
			if reqHeadersStr != "" {
				reqHeaders := strings.Split(reqHeadersStr, ",")
				for _, h := range reqHeaders {
					h = strings.TrimSpace(h)
					if h == "" {
						continue
					}
					allowed := false
					for _, ah := range allowedHeaders {
						if ah == "*" || strings.EqualFold(ah, h) {
							allowed = true
							break
						}
					}
					if !allowed {
						isAllowed = false
						message = fmt.Sprintf("Header '%s' is not allowed", h)
						checks = append(checks, fmt.Sprintf("Header check: FAILED (%s not in %v)", h, allowedHeaders))
						suggestions = append(suggestions, fmt.Sprintf("Add '%s' to Allowed Headers in CORS middleware configuration.", h))
						break
					}
				}
				if isAllowed {
					respHeaders["Access-Control-Allow-Headers"] = reqHeadersStr
					checks = append(checks, fmt.Sprintf("Headers check: Allowed (%s)", reqHeadersStr))
				}
			} else {
				checks = append(checks, "Headers check: Skipped (no requested headers)")
			}

			if isAllowed && len(exposedHeaders) > 0 {
				respHeaders["Access-Control-Expose-Headers"] = strings.Join(exposedHeaders, ", ")
				checks = append(checks, fmt.Sprintf("Exposed Headers: %v", exposedHeaders))
			}
			if isAllowed && maxAge > 0 {
				respHeaders["Access-Control-Max-Age"] = strconv.Itoa(maxAge)
				checks = append(checks, fmt.Sprintf("Max Age: %d seconds", maxAge))
			}
		}
	} else if isAllowed {
		// Regular request method check
		if slices.Contains(allowedMethods, req.Method) || slices.Contains(allowedMethods, "*") {
			checks = append(checks, fmt.Sprintf("Method check: Allowed (%s)", req.Method))
		} else {
			isAllowed = false
			message = fmt.Sprintf("Method '%s' is not allowed", req.Method)
			checks = append(checks, fmt.Sprintf("Method check: FAILED (%s not in %v)", req.Method, allowedMethods))
			suggestions = append(suggestions, fmt.Sprintf("Add '%s' to Allowed Methods in CORS middleware configuration.", req.Method))
		}
	}

	return &gateonv1.ValidateCORSResponse{
		IsAllowed:        isAllowed,
		Message:          message,
		ResponseHeaders:  respHeaders,
		Checks:           checks,
		IsPreflight:      isPreflight,
		MiddlewareConfig: mw.Config,
		RouteName:        routeName,
		Suggestions:      suggestions,
	}, nil
}

func parseList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	res := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			res = append(res, p)
		}
	}
	return res
}
