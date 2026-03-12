package server

import (
	"os"
	"strconv"
	"strings"

	"github.com/gateon/gateon/internal/logger"
	"github.com/rs/cors"
)

// BuildCORS returns CORS options from env. GATEON_CORS_ORIGINS, GATEON_CORS_ALLOW_CREDENTIALS.
func BuildCORS() *cors.Cors {
	originsStr := os.Getenv("GATEON_CORS_ORIGINS")
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
	allowCreds, _ := strconv.ParseBool(os.Getenv("GATEON_CORS_ALLOW_CREDENTIALS"))
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
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"Grpc-Status", "Grpc-Message", "Grpc-Encoding", "Grpc-Accept-Encoding"},
		AllowCredentials: allowCreds,
	})
}

