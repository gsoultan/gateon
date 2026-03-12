package middleware

import (
	"net/http"
	"regexp"
	"strings"
)

// RewriteConfig defines the configuration for the rewrite middleware.
type RewriteConfig struct {
	// Regexp is the regular expression to match against the request path.
	Regexp *regexp.Regexp
	// Replacement is the replacement string for the matched path.
	Replacement string
	// Path overrides the request path if not empty.
	Path string
	// AddQuery adds query parameters to the request.
	AddQuery map[string]string
}

// Rewrite returns a middleware that rewrites the request URL.
func Rewrite(cfg RewriteConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Path != "" {
				r.URL.Path = cfg.Path
			} else if cfg.Regexp != nil {
				r.URL.Path = cfg.Regexp.ReplaceAllString(r.URL.Path, cfg.Replacement)
			}

			if len(cfg.AddQuery) > 0 {
				q := r.URL.Query()
				for k, v := range cfg.AddQuery {
					q.Set(k, v)
				}
				r.URL.RawQuery = q.Encode()
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AddPrefix returns a middleware that adds a prefix to the request path.
func AddPrefix(prefix string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, prefix) {
				r.URL.Path = prefix + r.URL.Path
			}
			next.ServeHTTP(w, r)
		})
	}
}

// StripPrefix returns a middleware that strips a prefix from the request path.
func StripPrefix(prefixes []string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, prefix := range prefixes {
				if strings.HasPrefix(r.URL.Path, prefix) {
					r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
					if !strings.HasPrefix(r.URL.Path, "/") {
						r.URL.Path = "/" + r.URL.Path
					}
					// Traefik also sets X-Replaced-Path or similar?
					// For now just strip.
					break
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ReplacePath returns a middleware that replaces the request path.
func ReplacePath(path string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set("X-Replaced-Path", r.URL.Path)
			r.URL.Path = path
			next.ServeHTTP(w, r)
		})
	}
}

// StripPrefixRegex returns a middleware that strips a prefix from the request path using regex.
func StripPrefixRegex(regex string) (Middleware, error) {
	re, err := regexp.Compile(regex)
	if err != nil {
		return nil, err
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Path = re.ReplaceAllString(r.URL.Path, "")
			if !strings.HasPrefix(r.URL.Path, "/") {
				r.URL.Path = "/" + r.URL.Path
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}

// ReplacePathRegex returns a middleware that replaces the request path using regex.
func ReplacePathRegex(pattern, replacement string) (Middleware, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set("X-Replaced-Path", r.URL.Path)
			r.URL.Path = re.ReplaceAllString(r.URL.Path, replacement)
			next.ServeHTTP(w, r)
		})
	}, nil
}
