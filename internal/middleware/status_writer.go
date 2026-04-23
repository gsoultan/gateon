package middleware

import (
	"bufio"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// StatusResponseWriter wraps http.ResponseWriter to capture status code, bytes written, and TTFB.
// It also implements http.Flusher, http.Hijacker, and http.Pusher for transparency.
type StatusResponseWriter struct {
	http.ResponseWriter
	Status       int
	BytesWritten int64
	Country      string
	ttfbRecorded bool
	firstByte    time.Time
	start        time.Time
}

var statusCodes = make(map[int]string)

func init() {
	for i := 100; i < 600; i++ {
		statusCodes[i] = strconv.Itoa(i)
	}
}

func getStatusString(code int) string {
	if s, ok := statusCodes[code]; ok {
		return s
	}
	return strconv.Itoa(code)
}

var StatusResponseWriterPool = sync.Pool{
	New: func() any {
		return &StatusResponseWriter{}
	},
}

// GetStatusResponseWriter returns a pooled StatusResponseWriter.
func GetStatusResponseWriter(w http.ResponseWriter) *StatusResponseWriter {
	sw := StatusResponseWriterPool.Get().(*StatusResponseWriter)
	sw.ResponseWriter = w
	sw.Status = http.StatusOK
	sw.BytesWritten = 0
	sw.Country = ""
	sw.ttfbRecorded = false
	sw.firstByte = time.Time{}
	sw.start = time.Now()
	return sw
}

// PutStatusResponseWriter returns a StatusResponseWriter to the pool.
func PutStatusResponseWriter(sw *StatusResponseWriter) {
	sw.ResponseWriter = nil
	StatusResponseWriterPool.Put(sw)
}

func (w *StatusResponseWriter) WriteHeader(code int) {
	if !w.ttfbRecorded {
		w.firstByte = time.Now()
		w.ttfbRecorded = true
	}
	w.Status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *StatusResponseWriter) Write(b []byte) (int, error) {
	if !w.ttfbRecorded {
		w.firstByte = time.Now()
		w.ttfbRecorded = true
	}
	n, err := w.ResponseWriter.Write(b)
	w.BytesWritten += int64(n)
	return n, err
}

// TTFB returns the time-to-first-byte duration. Returns zero if no bytes were written.
func (w *StatusResponseWriter) TTFB() time.Duration {
	if !w.ttfbRecorded {
		return 0
	}
	return w.firstByte.Sub(w.start)
}

func (w *StatusResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *StatusResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (w *StatusResponseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}
