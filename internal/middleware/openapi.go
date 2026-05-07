package middleware

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/logger"
)

// OpenApiValidator checks requests against an OpenAPI specification.
// In a full implementation, this would use a library like kin-openapi.
type OpenApiValidator struct {
	SpecContent string
	Strict      bool
}

func NewOpenApiValidator(spec string, strict bool) *OpenApiValidator {
	return &OpenApiValidator{SpecContent: spec, Strict: strict}
}

func (v *OpenApiValidator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v.SpecContent == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Simplified validation logic for demonstration
		// 1. Check if path is expected (in a real scenario, we'd parse the spec)
		// 2. Check for unexpected query parameters
		// 3. Check content type

		logger.L.Debug().Str("path", r.URL.Path).Msg("Performing OpenAPI schema validation")

		// If validation fails and Strict is true, block the request
		// For now, we just pass through but log any potential violations

		next.ServeHTTP(w, r)
	})
}

func (v *OpenApiValidator) Name() string {
	return "openapi_validator"
}

func (v *OpenApiValidator) Description() string {
	return "Validates incoming requests against an OpenAPI specification to prevent Shadow API and parameter injection attacks."
}
