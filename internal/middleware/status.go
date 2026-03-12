package middleware

import "net/http"

// StatusResponseWriter is a wrapper around http.ResponseWriter that captures the status code.
type StatusResponseWriter struct {
	http.ResponseWriter
	StatusCode int
}

// NewStatusResponseWriter creates a new StatusResponseWriter.
func NewStatusResponseWriter(w http.ResponseWriter) *StatusResponseWriter {
	return &StatusResponseWriter{ResponseWriter: w, StatusCode: http.StatusOK}
}

func (w *StatusResponseWriter) WriteHeader(code int) {
	w.StatusCode = code
	w.ResponseWriter.WriteHeader(code)
}
