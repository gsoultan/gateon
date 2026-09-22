// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

const turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// TurnstileConfig configures the Cloudflare Turnstile verification middleware.
type TurnstileConfig struct {
	Secret     string   // Site secret key (required)
	HeaderName string   // Header containing the token (default CF-Turnstile-Response)
	Methods    []string // HTTP methods to verify; empty = all
}

// Turnstile returns a middleware that verifies Cloudflare Turnstile tokens.
// Skips verification for methods not in Methods; returns 400 if token missing or invalid.
func Turnstile(cfg TurnstileConfig) kind.Middleware {
	methodSet := make(map[string]bool)
	for _, m := range cfg.Methods {
		m := strings.TrimSpace(strings.ToUpper(m))
		if m != "" {
			methodSet[m] = true
		}
	}
	if len(methodSet) == 0 {
		methodSet["POST"] = true
		methodSet["PUT"] = true
		methodSet["PATCH"] = true
		methodSet["DELETE"] = true
	}

	headerName := cfg.HeaderName
	if headerName == "" {
		headerName = "CF-Turnstile-Response"
	}

	rt := turnstileRuntime{
		client:     &http.Client{Timeout: 10 * time.Second},
		secret:     cfg.Secret,
		headerName: headerName,
		methods:    methodSet,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rt.serve(next, w, r)
		})
	}
}

// turnstileRuntime is the config resolved once per route: the verification
// client, the secret, the header to read and the methods that require a token.
type turnstileRuntime struct {
	client     *http.Client
	secret     string
	headerName string
	methods    map[string]bool
}

func (t turnstileRuntime) serve(next http.Handler, w http.ResponseWriter, r *http.Request) {
	// Deliberately not gated on kind.ShouldSkipMetrics. That is a metrics
	// predicate: EntryPoint sets RouteName to "gateon-"+epLabel on every request
	// on every entrypoint, so its prefix test is always true and it collapses to
	// IsInternalPath(r.URL.Path) -- the client's own path. Measured: a client
	// resolving to a blocked country reached the origin with
	// GET /v1/security/anything while GET /normal/page got 403.
	//
	// internal/middleware/auth/hmac.go already says this: "Never gate a security
	// check on ShouldSkipMetrics -- it is a metrics predicate and using it here
	// would let any request matching it bypass HMAC." It had not reached here.
	if kind.IsCorsPreflight(r) || !t.methods[r.Method] {
		next.ServeHTTP(w, r)
		return
	}

	activeRouteID := kind.GetRouteName(r)
	token := t.tokenFrom(r)
	if token == "" {
		telemetry.MiddlewareTurnstileTotal.WithLabelValues(activeRouteID, "fail").Inc()
		http.Error(w, "Turnstile token required", http.StatusBadRequest)
		logger.L.LogDebug("turnstile: missing token", "path", r.URL.Path)
		return
	}

	remoteIP := request.GetClientIP(r, config.EffectiveTrustCloudflare())
	result, status, err := t.verify(r, token, remoteIP)
	if err != nil {
		http.Error(w, status.message, status.code)
		logger.L.LogError("turnstile: "+status.logMsg, "error", err)
		return
	}

	if !result.Success {
		telemetry.MiddlewareTurnstileTotal.WithLabelValues(activeRouteID, "fail").Inc()
		http.Error(w, fmt.Sprintf("Turnstile verification failed: %v", result.ErrorCodes), http.StatusBadRequest)
		logger.L.LogDebug("turnstile: verification failed",
			"error_codes", result.ErrorCodes,
			"path", r.URL.Path,
			"ip", remoteIP)
		return
	}

	telemetry.MiddlewareTurnstileTotal.WithLabelValues(activeRouteID, "pass").Inc()
	next.ServeHTTP(w, r)
}

// tokenFrom reads the challenge token from the configured header, falling back
// to the form field Cloudflare's widget posts.
//
// r.FormValue consumes the body on POST/PUT/PATCH, so the fallback tees the
// body aside while parsing and then puts it back -- the upstream still gets a
// complete request. Without that, reading the token would silently eat the
// payload the client sent.
func (t turnstileRuntime) tokenFrom(r *http.Request) string {
	if token := r.Header.Get(t.headerName); token != "" {
		return token
	}
	if r.Body == nil || r.Body == http.NoBody {
		return ""
	}

	buf := &bytes.Buffer{}
	originalBody := r.Body
	r.Body = struct {
		io.Reader
		io.Closer
	}{
		Reader: io.TeeReader(originalBody, buf),
		Closer: originalBody,
	}

	token := r.FormValue("cf-turnstile-response")

	r.Body = struct {
		io.Reader
		io.Closer
	}{
		Reader: io.MultiReader(buf, originalBody),
		Closer: originalBody,
	}
	return token
}

// turnstileFailure is how a verification error is reported to the client:
// deliberately not the underlying error, which names an upstream the caller
// has no business knowing about.
type turnstileFailure struct {
	code    int
	message string
	logMsg  string
}

type turnstileResult struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes,omitzero"`
}

func (t turnstileRuntime) verify(r *http.Request, token, remoteIP string) (turnstileResult, turnstileFailure, error) {
	form := url.Values{}
	form.Set("secret", t.secret)
	form.Set("response", token)
	form.Set("remoteip", remoteIP)

	var result turnstileResult

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, turnstileVerifyURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return result, turnstileFailure{http.StatusInternalServerError, "internal error", "create request failed"}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.client.Do(req)
	if err != nil {
		return result, turnstileFailure{http.StatusBadGateway, "verification service unavailable", "verify request failed"}, err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return result, turnstileFailure{http.StatusBadRequest, "verification failed", "decode response failed"}, err
	}
	return result, turnstileFailure{}, nil
}
