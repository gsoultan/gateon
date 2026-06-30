package middleware

import (
	"bufio"
	"compress/gzip"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
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

var brotliWriterPool = sync.Pool{
	New: func() any {
		return brotli.NewWriter(io.Discard)
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
	Algorithm            string   // Compression algorithm: auto (default), gzip, br
}

// Compress returns a middleware that compresses responses (auto selects br/gzip).
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
			activeRouteID := GetRouteName(r)
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

// CompressWithConfig returns a middleware that compresses responses with optional filters.
func CompressWithConfig(cfg CompressConfig) Middleware {
	minBytes := cfg.MinResponseBodyBytes
	if minBytes <= 0 {
		minBytes = defaultMinResponseBodyBytes
	}
	algorithm := normalizeCompressionAlgorithm(cfg.Algorithm)
	excluded := parseContentTypes(cfg.ExcludedContentTypes)
	included := parseContentTypes(cfg.IncludedContentTypes)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsCorsPreflight(r) || ShouldSkipMetrics(r) || r.Header.Get("Upgrade") != "" {
				next.ServeHTTP(w, r)
				return
			}

			acceptEncoding := r.Header.Get("Accept-Encoding")
			encoding := selectCompressionEncoding(acceptEncoding, algorithm)
			if encoding == "" {
				next.ServeHTTP(w, r)
				return
			}

			// gRPC must not be compressed
			if strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
				next.ServeHTTP(w, r)
				return
			}

			cw := &compressWriter{
				ResponseWriter: w,
				encoding:       encoding,
				minBytes:       minBytes,
				excluded:       excluded,
				included:       included,
				status:         http.StatusOK,
			}
			defer cw.Close()

			next.ServeHTTP(cw, r)
		})
	}
}

type compressWriter struct {
	http.ResponseWriter
	encoding string
	minBytes int
	excluded map[string]bool
	included map[string]bool

	status      int
	wroteHeader bool
	buf         []byte
	compressor  io.WriteCloser
	decided     bool
	should      bool
}

func (w *compressWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
}

func (w *compressWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.decided {
		if w.should {
			return w.compressor.Write(b)
		}
		return w.ResponseWriter.Write(b)
	}

	w.buf = append(w.buf, b...)
	if len(w.buf) >= w.minBytes {
		w.decide()
	}
	return len(b), nil
}

func (w *compressWriter) decide() {
	if w.decided {
		return
	}
	w.decided = true

	h := w.ResponseWriter.Header()
	// Skip if already encoded, or error, or small, or excluded type
	if h.Get("Content-Encoding") != "" || w.status >= 300 || w.status == http.StatusNoContent || w.status == http.StatusNotModified {
		w.should = false
	} else {
		contentType := strings.ToLower(strings.TrimSpace(strings.Split(h.Get("Content-Type"), ";")[0]))
		if excluded := w.excluded[contentType]; excluded {
			w.should = false
		} else if len(w.included) > 0 && !w.included[contentType] {
			w.should = false
		} else {
			w.should = true
		}
	}

	if w.should {
		h.Set("Content-Encoding", w.encoding)
		h.Del("Content-Length")
		h.Add("Vary", "Accept-Encoding")
		w.ResponseWriter.WriteHeader(w.status)
		if w.encoding == "br" {
			bw := brotliWriterPool.Get().(*brotli.Writer)
			bw.Reset(w.ResponseWriter)
			w.compressor = bw
		} else {
			gz := gzipWriterPool.Get().(*gzip.Writer)
			gz.Reset(w.ResponseWriter)
			w.compressor = gz
		}
		if len(w.buf) > 0 {
			_, _ = w.compressor.Write(w.buf)
		}
	} else {
		w.ResponseWriter.WriteHeader(w.status)
		if len(w.buf) > 0 {
			_, _ = w.ResponseWriter.Write(w.buf)
		}
	}
	w.buf = nil
}

func (w *compressWriter) Close() error {
	if !w.decided {
		w.decide()
	}
	if w.should && w.compressor != nil {
		err := w.compressor.Close()
		if w.encoding == "br" {
			brotliWriterPool.Put(w.compressor)
		} else {
			gzipWriterPool.Put(w.compressor)
		}
		w.compressor = nil
		return err
	}
	return nil
}

func (w *compressWriter) Flush() {
	if !w.decided {
		w.decide()
	}
	if w.should && w.compressor != nil {
		if f, ok := w.compressor.(interface{ Flush() error }); ok {
			_ = f.Flush()
		}
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *compressWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (w *compressWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
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

func normalizeCompressionAlgorithm(algorithm string) string {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "", "auto":
		return "auto"
	case "gzip":
		return "gzip"
	case "br", "brotli":
		return "br"
	default:
		return "auto"
	}
}

func selectCompressionEncoding(acceptEncoding string, algorithm string) string {
	isGzip := strings.Contains(acceptEncoding, "gzip")
	isBrotli := strings.Contains(acceptEncoding, "br")

	switch algorithm {
	case "gzip":
		if isGzip {
			return "gzip"
		}
	case "br":
		if isBrotli {
			return "br"
		}
	default:
		if isBrotli {
			return "br"
		}
		if isGzip {
			return "gzip"
		}
	}

	return ""
}
