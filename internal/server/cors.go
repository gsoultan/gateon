// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"os"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/server/mgmtorigin"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/rs/cors"
)

// parseAllowedOrigins returns the origins in GATEON_CORS_ORIGINS
// (comma-separated), or none when it is unset.
//
// It used to default to "*". The dashboard is served from the management
// origin and never needs CORS, so the default granted every site on the web
// read access to the unauthenticated endpoints and served no one (ADR 0041).
func parseAllowedOrigins() []string {
	var origins []string
	for o := range strings.SplitSeq(os.Getenv("GATEON_CORS_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			origins = append(origins, o)
		}
	}
	return origins
}

// managementOrigins returns the configured management CORS origins: the
// config's, or else GATEON_CORS_ORIGINS's.
func managementOrigins(cfg *gateonv1.ManagementConfig) []string {
	if cfg != nil && cfg.Cors != nil && len(cfg.Cors.AllowedOrigins) > 0 {
		return cfg.Cors.AllowedOrigins
	}
	return parseAllowedOrigins()
}

// BuildManagementOrigins returns the policy the management plane's write guard
// and WebSocket handshake check use: the management origin itself, plus the
// configured CORS origins. Read once at startup, as BuildManagementCORS is.
func BuildManagementOrigins(cfg *gateonv1.ManagementConfig) *mgmtorigin.Policy {
	return mgmtorigin.New(managementOrigins(cfg))
}

// grpcWebExposedHeaders are the response headers a gRPC-Web client must be able
// to read for Connect and gRPC-Web calls to work at all — the dashboard's entire
// API surface rides on them. They are always exposed, and operator-configured
// headers are added to them rather than replacing them: letting configuration
// substitute this list would let a well-meaning cors.exposed_headers setting
// break every dashboard request, with a failure that looks like a bug in the UI.
var grpcWebExposedHeaders = []string{
	"Grpc-Status", "Grpc-Message", "Grpc-Encoding", "Grpc-Accept-Encoding",
	"X-Grpc-Web", "X-Accept-Content-Transfer-Encoding", "X-Accept-Response-Streaming",
}

// mergeExposedHeaders unions the required gRPC-Web headers with the configured
// ones, preserving order and dropping duplicates and blanks.
func mergeExposedHeaders(configured []string) []string {
	seen := make(map[string]bool, len(grpcWebExposedHeaders)+len(configured))
	out := make([]string, 0, len(grpcWebExposedHeaders)+len(configured))
	for _, h := range append(append([]string{}, grpcWebExposedHeaders...), configured...) {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		// Header names are case-insensitive; dedupe accordingly so a differently
		// cased duplicate is not sent twice.
		key := strings.ToLower(h)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, h)
	}
	return out
}

// BuildManagementCORS returns CORS options for management API from config or
// env, or nil -- no CORS at all -- when no origin is configured.
func BuildManagementCORS(cfg *gateonv1.ManagementConfig) *cors.Cors {
	origins := managementOrigins(cfg)
	if len(origins) == 0 {
		return nil
	}
	var allowCreds bool
	var methods []string
	var headers []string
	var exposed []string
	var maxAge int

	if cfg != nil && cfg.Cors != nil {
		allowCreds = cfg.Cors.AllowCredentials
		methods = cfg.Cors.AllowedMethods
		headers = cfg.Cors.AllowedHeaders
		exposed = cfg.Cors.ExposedHeaders
		// A negative max_age is meaningless to browsers; clamp rather than send
		// it, since some treat a bad value as "do not cache" and others ignore
		// the whole preflight response.
		if m := cfg.Cors.MaxAge; m > 0 {
			maxAge = int(m)
		}
	}

	if !allowCreds {
		allowCreds, _ = strconv.ParseBool(os.Getenv("GATEON_CORS_ALLOW_CREDENTIALS"))
	}
	if len(methods) == 0 {
		methods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	}
	if len(headers) == 0 {
		headers = []string{"*"}
	}

	if allowCreds {
		for _, o := range origins {
			if o == "*" {
				allowCreds = false
				logger.L.LogWarn("CORS: AllowCredentials disabled when origins include *")
				break
			}
		}
	}
	return cors.New(cors.Options{
		AllowedOrigins:   origins,
		AllowedMethods:   methods,
		AllowedHeaders:   headers,
		ExposedHeaders:   mergeExposedHeaders(exposed),
		AllowCredentials: allowCreds,
		// Zero means the browser caches nothing, which is the previous
		// behaviour and stays the default when unset.
		MaxAge: maxAge,
	})
}
