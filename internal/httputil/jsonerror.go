package httputil

import (
	"encoding/json"
	"net/http"
)

// ErrorBody is the standard JSON shape for API error responses.
type ErrorBody struct {
	Error     string `json:"error"`
	Message   string `json:"message,omitempty"`
	Code      string `json:"code,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// WriteJSONError writes a JSON error response with the given status code and message.
func WriteJSONError(w http.ResponseWriter, statusCode int, message string, code string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	requestID := w.Header().Get("X-Request-ID")
	w.WriteHeader(statusCode)

	body := ErrorBody{
		Error:     message,
		Message:   message,
		Code:      code,
		RequestID: requestID,
	}
	_ = json.NewEncoder(w).Encode(body)
}
