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
	if req.Url == "" {
		return &gateonv1.ValidateCORSResponse{
			IsAllowed: false,
			Message:   "URL is required",
		}, nil
	}

	// 1. Find the matching route
	_, err := url.Parse(req.Url)
	if err != nil {
		return &gateonv1.ValidateCORSResponse{
			IsAllowed: false,
			Message:   fmt.Sprintf("Invalid URL: %v", err),
		}, nil
	}

	// Create a dummy http.Request for matching
	dummyReq, _ := http.NewRequest(req.Method, req.Url, nil)
	// Propagate headers to dummy request for proper route matching (e.g., Access-Control-Request-Method)
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
		}, nil
	}

	// 3. Simulate CORS logic
	return s.simulateCORS(req, corsMW, rt.Name)
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
			// Some simple methods are allowed by default even if not in AllowedMethods?
			// rs/cors documentation says AllowedMethods are methods that are allowed for actual requests.
			isAllowed = false
			message = fmt.Sprintf("Method '%s' is not allowed", req.Method)
			checks = append(checks, fmt.Sprintf("Method check: FAILED (%s not in %v)", req.Method, allowedMethods))
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
