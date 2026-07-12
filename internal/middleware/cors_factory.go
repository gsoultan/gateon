package middleware

import (
	"strconv"
)

func (f *Factory) createCORS(cfg map[string]string) (Middleware, error) {
	allowCredentials := parseBoolStrict(cfg["allow_credentials"], false)
	maxAge, _ := strconv.Atoi(cfg["max_age"])

	corsCfg := CORSConfig{
		AllowedOrigins:   parseListStrict(cfg["allowed_origins"]),
		AllowedMethods:   parseListStrict(cfg["allowed_methods"]),
		AllowedHeaders:   parseListStrict(cfg["allowed_headers"]),
		ExposedHeaders:   parseListStrict(cfg["exposed_headers"]),
		AllowCredentials: allowCredentials,
		MaxAge:           maxAge,
	}

	// Apply preset if specified
	corsCfg = ApplyCORSPreset(cfg, corsCfg)

	return CORS(corsCfg), nil
}
