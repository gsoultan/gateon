package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/kaptinlin/jsonschema"
)

type SchemaValidationConfig struct {
	Schema string
}

// SchemaValidation returns a middleware that validates JSON request bodies against a schema.
func SchemaValidation(cfg SchemaValidationConfig) Middleware {
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile([]byte(cfg.Schema))
	if err != nil {
		logger.L.Error().Err(err).Msg("failed to compile JSON schema")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only validate for methods that typically have a body and if schema is available
			if schema == nil || (r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch) {
				next.ServeHTTP(w, r)
				return
			}

			// Don't validate if content type is not JSON
			contentType := r.Header.Get("Content-Type")
			if contentType != "" && !jsonContentType(contentType) {
				next.ServeHTTP(w, r)
				return
			}

			// Read body
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Error reading request body", http.StatusBadRequest)
				return
			}
			// Restore body for next handlers
			r.Body = io.NopCloser(bytes.NewBuffer(body))

			if len(body) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			var input any
			if err := json.Unmarshal(body, &input); err != nil {
				logger.SecurityEvent("schema_validation_failed", r, "invalid JSON: "+err.Error())
				http.Error(w, "Invalid JSON", http.StatusBadRequest)
				return
			}

			result := schema.Validate(input)
			if !result.IsValid() {
				errMsg := "Schema validation failed"
				if len(result.Errors) > 0 {
					// Get first error from map
					for _, err := range result.Errors {
						errMsg += ": " + err.Message
						break
					}
				}
				logger.SecurityEvent("schema_validation_failed", r, errMsg)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":   "Schema validation failed",
					"details": result.Errors,
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func jsonContentType(ct string) bool {
	return ct == "application/json" || (len(ct) > 16 && ct[:16] == "application/json;")
}
