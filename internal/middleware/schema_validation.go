// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/kaptinlin/jsonschema"
)

type SchemaValidationConfig struct {
	Schema string
}

// SchemaValidation returns a middleware that validates JSON request bodies against a schema.
//
// A schema that does not compile is a configuration error and is refused
// here, at route build time. It used to be logged, after which the middleware
// passed every body through unvalidated -- a validation rule the dashboard
// showed as active and the gateway never applied.
func SchemaValidation(cfg SchemaValidationConfig) (Middleware, error) {
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile([]byte(cfg.Schema))
	if err != nil {
		return nil, fmt.Errorf("schema_validation: compile schema: %w", err)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only validate for methods that typically have a body
			if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
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
	}, nil
}

func jsonContentType(ct string) bool {
	return ct == "application/json" || (len(ct) > 16 && ct[:16] == "application/json;")
}
