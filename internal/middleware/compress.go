package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gsoultan/gateon/internal/telemetry"
)

const (
	defaultMinResponseBodyBytes = 1024
	defaultMaxBufferBytes       = 10 * 1024 * 1024 // 10MB
)

var gzipWriterPool = sync.Pool{
	New: func() any {
		return gzip.NewWriter(io.Discard)
	},
}

var compressBodyPool = sync.Pool{
	New: func() any {
		// Pre-allocate 4KB; will grow as needed up to maxBytes
		b := make([]byte, 0, 4096)
		return &b
	},
}

// CompressConfig configures the compress middleware (Traefik-style).
type CompressConfig struct {
	MinResponseBodyBytes int      // Minimum body size to compress; 0 = use default 1024
	ExcludedContentTypes []string // Content-Types to never compress
	IncludedContentTypes []string // If non-empty, only compress these; mutually exclusive with Excluded
	MaxBufferBytes       int      // Max response size to buffer; 0 = default 10MB
}

// Compress returns a middleware that compresses responses using gzip (no config).
func Compress() Middleware {
	return CompressWithConfig(CompressConfig{})
}

// CompressWithRoute returns a compress middleware that records compression ratio metrics.
func CompressWithRoute(cfg CompressConfig, routeID string) Middleware {
	inner := CompressWithConfig(cfg)
	return func(next http.Handler) http.Handler {
		wrapped := inner(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ShouldSkipMetrics(r) {
				next.ServeHTTP(w, r)
				return
			}
			activeRouteID := GetRouteID(r)
			if activeRouteID == "" {
				activeRouteID = routeID
			}

			sw, ok := w.(*StatusResponseWriter)
			var beforeBytes int64
			if ok {
				beforeBytes = sw.BytesWritten
			}
			wrapped.ServeHTTP(w, r)
			if ok {
				afterBytes := sw.BytesWritten - beforeBytes
				if afterBytes > 0 {
					telemetry.MiddlewareCompressBytesTotalOut.WithLabelValues(activeRouteID).Add(float64(afterBytes))
				}
			}
		})
	}
}

// CompressWithConfig returns a middleware that compresses responses using gzip with optional filters.
func CompressWithConfig(cfg CompressConfig) Middleware {
	minBytes := cfg.MinResponseBodyBytes
	if minBytes <= 0 {
		minBytes = defaultMinResponseBodyBytes
	}
	maxBuf := cfg.MaxBufferBytes
	if maxBuf <= 0 {
		maxBuf = defaultMaxBufferBytes
	}
	excluded := parseContentTypes(cfg.ExcludedContentTypes)
	included := parseContentTypes(cfg.IncludedContentTypes)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ShouldSkipMetrics(r) {
				next.ServeHTTP(w, r)
				return
			}
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				next.ServeHTTP(w, r)
				return
			}

			// gRPC must not be compressed
			if strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
				next.ServeHTTP(w, r)
				return
			}

			bodyBuf := compressBodyPool.Get().(*[]byte)
			*bodyBuf = (*bodyBuf)[:0]
			rec := &compressRecorder{ResponseWriter: w, status: 200, maxBytes: maxBuf, body: *bodyBuf}
			next.ServeHTTP(rec, r)

			// Already compressed or error - pass through
			if rec.Header().Get("Content-Encoding") != "" || rec.status >= 300 {
				rec.flushRaw(false)
				rec.returnBody()
				return
			}

			contentType := strings.ToLower(strings.TrimSpace(strings.Split(rec.Header().Get("Content-Type"), ";")[0]))
			if excluded[contentType] {
				rec.flushRaw(false)
				rec.returnBody()
				return
			}
			if len(included) > 0 && !included[contentType] {
				rec.flushRaw(false)
				rec.returnBody()
				return
			}
			if len(rec.body) < minBytes {
				rec.flushRaw(false)
				rec.returnBody()
				return
			}

			for k, v := range rec.Header() {
				for _, vv := range v {
					w.Header().Add(k, vv)
				}
			}
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Del("Content-Length")
			w.WriteHeader(rec.status)
			gz := gzipWriterPool.Get().(*gzip.Writer)
			gz.Reset(w)
			_, _ = gz.Write(rec.body)
			gz.Close()
			gzipWriterPool.Put(gz)
			rec.returnBody()
		})
	}
}

func parseContentTypes(ct []string) map[string]bool {
	m := make(map[string]bool)
	for _, s := range ct {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			m[s] = true
		}
	}
	return m
}

type compressRecorder struct {
	http.ResponseWriter
	status     int
	body       []byte
	maxBytes   int
	header     http.Header
	wrote      bool
	overflowed bool // true once we exceeded buffer and switched to pass-through
}

func (r *compressRecorder) Header() http.Header {
	if r.header == nil {
		r.header = make(http.Header)
	}
	return r.header
}

func (r *compressRecorder) WriteHeader(code int) {
	if r.wrote {
		return
	}
	r.status = code
	r.wrote = true
}

func (r *compressRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(http.StatusOK)
	}
	if r.header == nil {
		r.header = make(http.Header)
	}
	if r.overflowed {
		return r.ResponseWriter.Write(b)
	}
	if len(r.body)+len(b) <= r.maxBytes {
		r.body = append(r.body, b...)
		return len(b), nil
	}
	// Exceeded buffer: flush buffered data raw (no Content-Length; streaming), then pass through
	r.overflowed = true
	r.flushRaw(true)
	return r.ResponseWriter.Write(b)
}

func (r *compressRecorder) flushRaw(streaming bool) {
	if r.header != nil {
		for k, v := range r.header {
			for _, vv := range v {
				r.ResponseWriter.Header().Add(k, vv)
			}
		}
	}
	if !streaming {
		r.ResponseWriter.Header().Set("Content-Length", strconv.Itoa(len(r.body)))
	}
	r.ResponseWriter.WriteHeader(r.status)
	_, _ = r.ResponseWriter.Write(r.body)
}

// returnBody returns the body buffer to the pool for reuse.
func (r *compressRecorder) returnBody() {
	if r.body != nil {
		b := r.body
		compressBodyPool.Put(&b)
		r.body = nil
	}
}
