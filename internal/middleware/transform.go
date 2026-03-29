package middleware

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// BodyTransformConfig configures the body transformation middleware.
type BodyTransformConfig struct {
	RequestSearch     string
	RequestReplace    string
	ResponseSearch    string
	ResponseReplace   string
	ContentTypeFilter string // e.g. "application/json"
}

// BodyTransform returns a middleware that replaces strings in request and response bodies.
func BodyTransform(cfg BodyTransformConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Content-Type check
			if cfg.ContentTypeFilter != "" {
				ct := r.Header.Get("Content-Type")
				if !strings.Contains(ct, cfg.ContentTypeFilter) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Request transformation
			if cfg.RequestSearch != "" && r.Body != nil {
				body, err := io.ReadAll(r.Body)
				if err == nil {
					_ = r.Body.Close()
					newBody := strings.ReplaceAll(string(body), cfg.RequestSearch, cfg.RequestReplace)
					r.Body = io.NopCloser(bytes.NewBufferString(newBody))
					r.ContentLength = int64(len(newBody))
					r.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
				}
			}

			if cfg.ResponseSearch == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Response transformation
			bw := &transformResponseWriter{ResponseWriter: w, body: &bytes.Buffer{}}
			next.ServeHTTP(bw, r)

			// Only transform if status is 200 OK or similar
			if bw.status >= 400 {
				w.Write(bw.body.Bytes())
				return
			}

			respBody := bw.body.String()
			newRespBody := strings.ReplaceAll(respBody, cfg.ResponseSearch, cfg.ResponseReplace)
			w.Header().Set("Content-Length", strconv.Itoa(len(newRespBody)))

			// Remove ETag if present, as body has changed
			w.Header().Del("ETag")

			w.Write([]byte(newRespBody))
		})
	}
}

type transformResponseWriter struct {
	http.ResponseWriter
	body   *bytes.Buffer
	status int
}

func (bw *transformResponseWriter) Write(b []byte) (int, error) {
	return bw.body.Write(b)
}

func (bw *transformResponseWriter) WriteHeader(code int) {
	bw.status = code
	bw.ResponseWriter.WriteHeader(code)
}

func (bw *transformResponseWriter) Flush() {
	if f, ok := bw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
