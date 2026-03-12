package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
)

var gzipWriterPool = sync.Pool{
	New: func() any {
		return gzip.NewWriter(io.Discard)
	},
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func (w gzipResponseWriter) WriteHeader(code int) {
	w.ResponseWriter.WriteHeader(code)
}

// Compress returns a middleware that compresses responses using gzip.
func Compress() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("Content-Encoding", "gzip")
			gz := gzipWriterPool.Get().(*gzip.Writer)
			gz.Reset(w)
			defer func() {
				gz.Close()
				gzipWriterPool.Put(gz)
			}()

			gzw := gzipResponseWriter{Writer: gz, ResponseWriter: w}
			next.ServeHTTP(gzw, r)
		})
	}
}
