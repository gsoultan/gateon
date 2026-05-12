package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
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
func Turnstile(cfg TurnstileConfig) Middleware {
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

	client := &http.Client{Timeout: 10 * time.Second}
	secret := cfg.Secret
	headerName := cfg.HeaderName
	if headerName == "" {
		headerName = "CF-Turnstile-Response"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsCorsPreflight(r) || ShouldSkipMetrics(r) {
				next.ServeHTTP(w, r)
				return
			}
			activeRouteID := GetRouteName(r)

			if !methodSet[r.Method] {
				next.ServeHTTP(w, r)
				return
			}

			token := r.Header.Get(headerName)
			if token == "" {
				token = r.FormValue("cf-turnstile-response")
			}
			if token == "" {
				telemetry.MiddlewareTurnstileTotal.WithLabelValues(activeRouteID, "fail").Inc()
				http.Error(w, "Turnstile token required", http.StatusBadRequest)
				logger.L.LogDebug("turnstile: missing token", "path", r.URL.Path)
				return
			}

			remoteIP := request.GetClientIP(r, request.TrustCloudflareFromEnv())
			form := url.Values{}
			form.Set("secret", secret)
			form.Set("response", token)
			form.Set("remoteip", remoteIP)

			req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, turnstileVerifyURL, bytes.NewBufferString(form.Encode()))
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				logger.L.LogError("turnstile: create request failed", "error", err)
				return
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := client.Do(req)
			if err != nil {
				http.Error(w, "verification service unavailable", http.StatusBadGateway)
				logger.L.LogError("turnstile: verify request failed", "error", err)
				return
			}
			defer resp.Body.Close()

			var result struct {
				Success    bool     `json:"success"`
				ErrorCodes []string `json:"error-codes,omitzero"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				http.Error(w, "verification failed", http.StatusBadRequest)
				logger.L.LogWarn("turnstile: decode response failed", "error", err)
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
		})
	}
}
