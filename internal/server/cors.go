package server

import (
	"os"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/rs/cors"
)

// parseAllowedOrigins returns allowed origins from GATEON_CORS_ORIGINS (comma-separated).
// Defaults to ["*"] when unset or empty.
func parseAllowedOrigins(envVar string) []string {
	originsStr := os.Getenv(envVar)
	if originsStr == "" && envVar != "GATEON_CORS_ORIGINS" {
		originsStr = os.Getenv("GATEON_CORS_ORIGINS")
	}
	if originsStr == "" {
		originsStr = "*"
	}
	var origins []string
	for _, o := range strings.Split(originsStr, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			origins = append(origins, o)
		}
	}
	if len(origins) == 0 {
		origins = []string{"*"}
	}
	return origins
}

// BuildManagementCORS returns CORS options for management API from config or env.
func BuildManagementCORS(cfg *gateonv1.ManagementConfig) *cors.Cors {
	var origins []string
	var allowCreds bool
	var methods []string
	var headers []string

	if cfg != nil && cfg.Cors != nil {
		origins = cfg.Cors.AllowedOrigins
		allowCreds = cfg.Cors.AllowCredentials
		methods = cfg.Cors.AllowedMethods
		headers = cfg.Cors.AllowedHeaders
	}

	if len(origins) == 0 {
		origins = parseAllowedOrigins("GATEON_CORS_ORIGINS")
	}
	if !allowCreds {
		allowCreds, _ = strconv.ParseBool(os.Getenv("GATEON_CORS_ALLOW_CREDENTIALS"))
	}
	if len(methods) == 0 {
		methods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	}
	if len(headers) == 0 {
		headers = []string{"*"}
	}

	if allowCreds {
		for _, o := range origins {
			if o == "*" {
				allowCreds = false
				logger.L.Warn().Msg("CORS: AllowCredentials disabled when origins include *")
				break
			}
		}
	}
	return cors.New(cors.Options{
		AllowedOrigins:   origins,
		AllowedMethods:   methods,
		AllowedHeaders:   headers,
		ExposedHeaders:   []string{"Grpc-Status", "Grpc-Message", "Grpc-Encoding", "Grpc-Accept-Encoding"},
		AllowCredentials: allowCreds,
	})
}
