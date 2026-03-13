package middleware

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultForwardAuthTimeout = 10 * time.Second

// ForwardAuthConfig configures the forward-auth middleware (Traefik-style).
type ForwardAuthConfig struct {
	Address               string   // Auth service URL (required)
	TrustForwardHeader    bool     // Trust X-Forwarded-* from incoming request
	AuthResponseHeaders   []string // Headers from auth 2xx to copy to the forwarded request
	AuthRequestHeaders    []string // Headers to forward to auth; empty = all
	ForwardBody           bool     // Forward request body to auth service
	PreserveRequestMethod bool     // Use same HTTP method; if false, use GET
	MaxBodySize           int64    // Max body size when forwarding; 0 = 1MB default, -1 = unlimited
	TLSInsecureSkipVerify bool     // Skip TLS cert verification (for dev)
}

// ForwardAuth returns a middleware that delegates auth to an external service.
func ForwardAuth(cfg ForwardAuthConfig) (Middleware, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("forwardauth requires address")
	}
	authURL, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("forwardauth invalid address: %w", err)
	}
	if authURL.Scheme == "" || authURL.Host == "" {
		return nil, fmt.Errorf("forwardauth address must be absolute URL (e.g. https://auth.example.com/verify)")
	}

	authResponseSet := make(map[string]bool)
	for _, h := range cfg.AuthResponseHeaders {
		authResponseSet[http.CanonicalHeaderKey(strings.TrimSpace(h))] = true
	}

	authRequestSet := make(map[string]bool)
	for _, h := range cfg.AuthRequestHeaders {
		authRequestSet[http.CanonicalHeaderKey(strings.TrimSpace(h))] = true
	}

	maxBody := cfg.MaxBodySize
	if maxBody == 0 {
		maxBody = 1024 * 1024 // 1MB default
	}

	client := &http.Client{
		Timeout: defaultForwardAuthTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if authURL.Scheme == "https" && cfg.TLSInsecureSkipVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			method := "GET"
			if cfg.PreserveRequestMethod {
				method = r.Method
			}

			var bodyBuf []byte
			if cfg.ForwardBody && (r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH") {
				var err error
				if maxBody >= 0 {
					bodyBuf, err = io.ReadAll(io.LimitReader(r.Body, maxBody))
				} else {
					bodyBuf, err = io.ReadAll(r.Body)
				}
				if err != nil {
					http.Error(w, "failed to read body", http.StatusBadRequest)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(bodyBuf))
			}

			var bodyReader io.Reader
			if len(bodyBuf) > 0 {
				bodyReader = bytes.NewReader(bodyBuf)
			}

			authReq, err := http.NewRequestWithContext(r.Context(), method, cfg.Address, bodyReader)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			// X-Forwarded-* headers (Traefik-style)
			authReq.Header.Set("X-Forwarded-Method", r.Method)
			authReq.Header.Set("X-Forwarded-Proto", scheme(r))
			authReq.Header.Set("X-Forwarded-Host", r.Host)
			authReq.Header.Set("X-Forwarded-Uri", r.URL.RequestURI())
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" && cfg.TrustForwardHeader {
				authReq.Header.Set("X-Forwarded-For", xff)
			} else {
				authReq.Header.Set("X-Forwarded-For", clientIP(r))
			}

			// Copy request headers
			for k, vv := range r.Header {
				canon := http.CanonicalHeaderKey(k)
				if len(authRequestSet) == 0 || authRequestSet[canon] {
					for _, v := range vv {
						authReq.Header.Add(k, v)
					}
				}
			}

			resp, err := client.Do(authReq)
			if err != nil {
				http.Error(w, "auth service unavailable", http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				// Return auth service response to client
				for k, vv := range resp.Header {
					for _, v := range vv {
						w.Header().Add(k, v)
					}
				}
				w.WriteHeader(resp.StatusCode)
				_, _ = io.Copy(w, resp.Body)
				return
			}

			// Auth OK: copy auth_response_headers to request
			if len(authResponseSet) > 0 {
				for k, vv := range resp.Header {
					if authResponseSet[http.CanonicalHeaderKey(k)] {
						for _, v := range vv {
							r.Header.Set(k, v)
						}
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if s := r.Header.Get("X-Forwarded-Proto"); s != "" {
		return s
	}
	return "http"
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i >= 0 {
		ip = ip[:i]
	}
	return ip
}
