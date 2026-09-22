// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import "strings"

// securityMiddlewareTypes are the middleware whose absence removes a control
// rather than a convenience.
//
// The distinction decides what happens when one cannot be built. A route that
// names a middleware and does not get it is not the route the operator
// configured, but the cost of serving anyway is very different for a header
// rewrite than for authentication: one renders a page slightly wrong, the
// other publishes it.
//
// Kept as an explicit list rather than derived from the config, because the
// safe direction is to fail closed on anything unrecognised -- a middleware
// type added later is treated as security-relevant until someone decides
// otherwise, which is the error that costs least.
var securityMiddlewareTypes = map[string]struct{}{
	"auth": {}, "oidc": {}, "forwardauth": {}, "hmac": {},
	"waf": {}, "ipfilter": {}, "geoip": {}, "policy": {},
	"schema_validation": {}, "graphql_firewall": {}, "file_security": {},
	"bot_management": {}, "turnstile": {}, "pow": {}, "tls_binding": {},
	"honeypot": {}, "deception": {}, "tarpit": {}, "entropy": {},
	"xss_recognition": {}, "sqli_recognition": {}, "threat_recognition": {},
	"security_headers": {}, "xfcc": {},
}

// cosmeticMiddlewareTypes are the ones whose absence degrades behaviour
// without removing a boundary. Everything not named here is treated as
// security-relevant.
var cosmeticMiddlewareTypes = map[string]struct{}{
	"headers": {}, "forwardedheaders": {}, "rewrite": {}, "addprefix": {},
	"stripprefix": {}, "stripprefixregex": {}, "replacepath": {},
	"replacepathregex": {}, "accesslog": {}, "metrics": {}, "compress": {},
	"errors": {}, "retry": {}, "cors": {}, "grpcweb": {}, "request_id": {},
	"cache": {}, "transform": {}, "circuit_breaker": {}, "wasm": {},
	"ratelimit": {}, "inflightreq": {}, "buffering": {},
}

// isSecurityMiddleware reports whether failing to build this type should take
// the route out of service rather than quietly serving without it.
//
// Both lists are consulted so that a type in neither is visible as an
// oversight rather than silently inheriting a default -- and the default it
// inherits is "security", because that is the direction where being wrong
// costs least. TestEveryMiddlewareTypeIsClassified asserts the two lists
// partition every case the factory can build.
func isSecurityMiddleware(mwType string) bool {
	t := strings.ToLower(strings.TrimSpace(mwType))
	if _, ok := securityMiddlewareTypes[t]; ok {
		return true
	}
	if _, ok := cosmeticMiddlewareTypes[t]; ok {
		return false
	}
	return true
}
