// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/kaptinlin/jsonschema"
)

type SchemaValidationConfig struct {
	Schema string
	// MaxBodyBytes is the longest body validated; a longer one is refused
	// with 413 before any of it is decoded. 0 is the resource profile's
	// default (TierDefaults.SchemaMaxBodyBytes).
	MaxBodyBytes int64
}

// Decoding JSON into `any` holds 6 to 45 times the input's length -- 45 for an
// array of small objects -- and the body used to be read up to the gateway's
// 10 MiB request limit and decoded whole: one 10 MiB array held about 225 MiB
// live, and nothing bounded how many ran at once (ADR 0075). So the body has a
// bound of its own, and a body past schemaLargeBody needs a decode slot.
const (
	schemaMaxBodyEnv    = "GATEON_SCHEMA_VALIDATION_MAX_BODY_BYTES"
	schemaLargeBodyEnv  = "GATEON_SCHEMA_VALIDATION_MAX_LARGE_BODIES"
	schemaLargeBody     = 64 << 10
	schemaDecodeWait    = 2 * time.Second
	schemaDecodeRetryIn = "2"
)

// schemaDecodeGate bounds how many bodies over schemaLargeBody are decoded at
// once in the whole process. It is its own gate rather than the WAF's
// large-body slots (ADR 0069): a WAF earlier in the chain holds its slot until
// the request has been proxied, so a validation after it waiting on the same
// slots is hold-and-wait, and a burst as large as the slot count would wait
// out every request and shed all of them.
type schemaDecodeGate struct {
	once  sync.Once
	slots chan struct{}
}

var schemaDecodes schemaDecodeGate

// acquire takes a slot, waiting at most schemaDecodeWait or until ctx ends.
// The release it returns is safe to call once and never nil.
func (g *schemaDecodeGate) acquire(ctx context.Context) (func(), bool) {
	g.once.Do(func() {
		n := envPositive(schemaLargeBodyEnv, int64(config.CurrentTierDefaults().SchemaMaxLargeBodies))
		g.slots = make(chan struct{}, max(1, n))
	})
	release := func() { <-g.slots }
	select {
	case g.slots <- struct{}{}:
		return release, true
	default:
	}
	timer := time.NewTimer(schemaDecodeWait)
	defer timer.Stop()
	select {
	case g.slots <- struct{}{}:
		return release, true
	case <-timer.C:
	case <-ctx.Done():
	}
	return func() {}, false
}

// envPositive is the named variable when it is a positive integer, else def.
// A value that is set and not a positive integer is ignored with a warning.
func envPositive(name string, def int64) int64 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
		return n
	}
	logger.L.LogWarn("ignoring an invalid schema validation bound; using the profile default",
		"env", name, "value", v)
	return def
}

// NewSchemaValidation builds the middleware from a route's config map. A
// max_body_bytes that is not a positive integer is a configuration error.
func NewSchemaValidation(cfg map[string]string) (kind.Middleware, error) {
	c := SchemaValidationConfig{Schema: cfg["schema"]}
	if v := strings.TrimSpace(cfg["max_body_bytes"]); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("schema_validation: max_body_bytes %q is not a positive integer", v)
		}
		c.MaxBodyBytes = n
	}
	return SchemaValidation(c)
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
	limit := cfg.MaxBodyBytes
	if limit <= 0 {
		limit = envPositive(schemaMaxBodyEnv, config.CurrentTierDefaults().SchemaMaxBodyBytes)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !bodyIsValidatable(r) {
				next.ServeHTTP(w, r)
				return
			}
			body, ok := readSchemaBody(w, r, limit)
			if !ok {
				return
			}
			// Restore the body for the handlers downstream.
			r.Body = io.NopCloser(bytes.NewBuffer(body))
			if len(body) > 0 && !validateSchemaBody(w, r, schema, body) {
				return
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}

// readSchemaBody reads the body, refusing with 413 one longer than limit
// without reading more than one byte past it. It reports whether to go on.
func readSchemaBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	if r.ContentLength > limit {
		http.Error(w, "Request body too large to validate", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return nil, false
	}
	if int64(len(body)) > limit {
		http.Error(w, "Request body too large to validate", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	return body, true
}

// validateSchemaBody decodes and validates body, answering the client when it
// fails, and reports whether it passed. A body past schemaLargeBody is decoded
// only once it holds a decode slot, which it gives back before the request
// goes on; with none free it is refused with 503 and never forwarded
// unvalidated.
func validateSchemaBody(w http.ResponseWriter, r *http.Request, schema *jsonschema.Schema, body []byte) bool {
	if len(body) > schemaLargeBody {
		release, ok := schemaDecodes.acquire(r.Context())
		defer release()
		if !ok {
			w.Header().Set("Retry-After", schemaDecodeRetryIn)
			http.Error(w, "Service Unavailable (request body could not be validated yet; retry)",
				http.StatusServiceUnavailable)
			return false
		}
	}
	var input any
	if err := json.Unmarshal(body, &input); err != nil {
		logger.SecurityEvent("schema_validation_failed", r, "invalid JSON: "+err.Error())
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return false
	}
	if result := schema.Validate(input); !result.IsValid() {
		writeSchemaFailure(w, r, result)
		return false
	}
	return true
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
	// Case-insensitive, and tolerant of space before the parameter list.
	// A media type is case-insensitive per RFC 9110, and Express, Spring and
	// ASP.NET all parse "Application/json" as JSON and hand it to the
	// application -- so a byte-exact comparison here meant the body reached
	// the origin unvalidated while the origin treated it as JSON anyway.
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "application/json" {
		return true
	}
	base, _, found := strings.Cut(ct, ";")
	return found && strings.TrimSpace(base) == "application/json"
}
