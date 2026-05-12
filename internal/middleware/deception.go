package middleware

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
)

// DeceptionConfig defines configuration for Deception middleware.
type DeceptionConfig struct {
	HoneypotPaths        []string
	InjectInvisibleLinks bool
	InvisibleLinkPaths   []string
	HoneyForms           []string // Injected hidden forms
	RouteID              string
	EnableTrollResponse  bool
	CanaryHeader         string // attractive-looking header name
	CanaryToken          string // attractive-looking header value
}

// Deception middleware provides path honeypots, invisible link injection, and canary tokens.
func Deception(cfg DeceptionConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path

			// 1. Check for Canary Token reuse
			if cfg.CanaryHeader != "" && cfg.CanaryToken != "" {
				if r.Header.Get(cfg.CanaryHeader) == cfg.CanaryToken {
					recordAdvancedThreat(r, "canary_token_reused", 100, "Attacker reused injected canary header: "+cfg.CanaryHeader, cfg.RouteID)
					if cfg.EnableTrollResponse {
						serveTrollResponse(w)
					} else {
						http.Error(w, "Forbidden", http.StatusForbidden)
					}
					return
				}
			}

			// 2. Check for honeypot path access
			for _, trap := range cfg.HoneypotPaths {
				if trap != "" && (path == trap || strings.HasPrefix(path, trap+"/")) {
					recordAdvancedThreat(r, "honeypot_triggered", 100, "Access to trap path: "+trap, cfg.RouteID)
					if cfg.EnableTrollResponse {
						serveTrollResponse(w)
					} else {
						http.Error(w, "Forbidden", http.StatusForbidden)
					}
					return
				}
			}

			// 3. Check for invisible link access
			for _, link := range cfg.InvisibleLinkPaths {
				if link != "" && path == link {
					recordAdvancedThreat(r, "deception_link_triggered", 100, "Access to invisible deception link: "+link, cfg.RouteID)
					if cfg.EnableTrollResponse {
						serveTrollResponse(w)
					} else {
						http.Error(w, "Forbidden", http.StatusForbidden)
					}
					return
				}
			}

			// 4. Inject Canary Header into response
			if cfg.CanaryHeader != "" && cfg.CanaryToken != "" {
				w.Header().Set(cfg.CanaryHeader, cfg.CanaryToken)
			}

			if (!cfg.InjectInvisibleLinks || len(cfg.InvisibleLinkPaths) == 0) && len(cfg.HoneyForms) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Wrap response to inject tokens if it's HTML
			drw := &deceptionResponseWriter{
				ResponseWriter: w,
				cfg:            cfg,
			}
			next.ServeHTTP(drw, r)
		})
	}
}

type deceptionResponseWriter struct {
	http.ResponseWriter
	cfg         DeceptionConfig
	wroteHeader bool
}

func (w *deceptionResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	contentType := w.Header().Get("Content-Type")
	if code == http.StatusOK && strings.Contains(contentType, "text/html") {
		w.Header().Del("Content-Length")
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *deceptionResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		if idx := bytes.LastIndex(b, []byte("</body>")); idx != -1 {
			var sb strings.Builder
			for _, link := range w.cfg.InvisibleLinkPaths {
				sb.WriteString(fmt.Sprintf(`<a href="%s" style="display:none" aria-hidden="true" tabIndex="-1"></a>`, link))
			}
			for _, form := range w.cfg.HoneyForms {
				sb.WriteString(fmt.Sprintf(`<form action="%s" method="POST" style="display:none" aria-hidden="true"><input type="text" name="admin_password"></form>`, form))
			}

			newContent := make([]byte, 0, len(b)+sb.Len())
			newContent = append(newContent, b[:idx]...)
			newContent = append(newContent, sb.String()...)
			newContent = append(newContent, b[idx:]...)
			return w.ResponseWriter.Write(newContent)
		}
	}

	return w.ResponseWriter.Write(b)
}
