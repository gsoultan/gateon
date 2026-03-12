package httputil

import (
	"encoding/json"
	"net/http"
)

// ErrorBody is the standard JSON shape for API error responses.
type ErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    string `json:"code,omitempty"`
}

// WriteJSONError writes a JSON error response with the given status code and message.
// If code is empty, Message is used for the "error" field; otherwise both are set.
func WriteJSONError(w http.ResponseWriter, statusCode int, message string, code string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	body := ErrorBody{Error: message, Message: message}
	if code != "" {
		body.Code = code
	}
	_ = json.NewEncoder(w).Encode(body)
}
