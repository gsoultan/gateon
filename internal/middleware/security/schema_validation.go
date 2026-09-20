// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
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
func SchemaValidation(cfg SchemaValidationConfig) (kind.Middleware, error) {
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile([]byte(cfg.Schema))
	if err != nil {
		return nil, fmt.Errorf("schema_validation: compile schema: %w", err)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !bodyIsValidatable(r) {
				next.ServeHTTP(w, r)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Error reading request body", http.StatusBadRequest)
				return
			}
			// Restore the body for the handlers downstream.
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

			if result := schema.Validate(input); !result.IsValid() {
				writeSchemaFailure(w, r, result)
				return
			}

			next.ServeHTTP(w, r)
		})
	}, nil
}

// bodyIsValidatable reports whether this request carries a JSON body worth
// checking: a method that normally has one, and either no declared content
// type or a JSON one.
func bodyIsValidatable(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return false
	}
	ct := r.Header.Get("Content-Type")
	return ct == "" || jsonContentType(ct)
}

// writeSchemaFailure records the refusal and answers the client. The message
// logged carries the first validation error; the body carries them all.
func writeSchemaFailure(w http.ResponseWriter, r *http.Request, result *jsonschema.EvaluationResult) {
	errMsg := "Schema validation failed"
	for _, err := range result.Errors {
		errMsg += ": " + err.Message
		break
	}
	logger.SecurityEvent("schema_validation_failed", r, errMsg)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":   "Schema validation failed",
		"details": result.Errors,
	})
}

func jsonContentType(ct string) bool {
	return ct == "application/json" || (len(ct) > 16 && ct[:16] == "application/json;")
}
