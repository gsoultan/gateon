package httputil

import "net/http"

// StatusRecorder wraps ResponseWriter to capture the status code.
type StatusRecorder struct {
	http.ResponseWriter
	Status int
}

func (r *StatusRecorder) WriteHeader(code int) {
	r.Status = code
	r.ResponseWriter.WriteHeader(code)
}
