package middleware

import (
	"net/http"
)

// ErrorsConfig defines the configuration for the errors middleware.
type ErrorsConfig struct {
	// StatusCodes is the list of status codes that should trigger the custom error page.
	StatusCodes []int
	// CustomPages is a map of status code to custom HTML body.
	CustomPages map[int]string
}

// errorResponseWriter wraps http.ResponseWriter to intercept error status codes
// and replace the response body with a custom error page.
type errorResponseWriter struct {
	http.ResponseWriter
	status      int
	matchedPage string
	wroteHeader bool
	codes       []int
	pages       map[int]string
}

func (w *errorResponseWriter) WriteHeader(code int) {
	if w.wroteHeader || w.matchedPage != "" {
		return
	}
	w.status = code
	if page, ok := w.pages[code]; ok {
		w.matchedPage = page
		return
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *errorResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.matchedPage != "" {
		// Drop the downstream error body as we'll replace it.
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// Errors returns a middleware that handles custom error pages by intercepting
// error status codes and replacing the response body.
func Errors(cfg ErrorsConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ew := &errorResponseWriter{
				ResponseWriter: w,
				codes:          cfg.StatusCodes,
				pages:          cfg.CustomPages,
			}
			next.ServeHTTP(ew, r)

			if ew.matchedPage != "" {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(ew.status)
				_, _ = w.Write([]byte(ew.matchedPage))
			}
		})
	}
}
