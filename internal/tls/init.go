package tls

import (
	"os"
	"strings"
)

// InitFromEnv initializes TLS config from environment variables.
func InitFromEnv() Config {
	enabled := os.Getenv("GATEON_TLS_ENABLED") == "true"
	minVer := os.Getenv("GATEON_TLS_MIN_VERSION")
	if minVer == "" {
		minVer = "TLS1.2"
	}
	cfg := Config{
		Enabled:        enabled,
		Email:          os.Getenv("GATEON_TLS_EMAIL"),
		Domains:        splitAndTrim(os.Getenv("GATEON_TLS_DOMAINS")),
		CacheDir:       os.Getenv("GATEON_TLS_CACHE_DIR"),
		MinVersion:     minVer,
		MaxVersion:     os.Getenv("GATEON_TLS_MAX_VERSION"),
		ClientAuthType: os.Getenv("GATEON_TLS_CLIENT_AUTH_TYPE"),
		CipherSuites:   splitAndTrim(os.Getenv("GATEON_TLS_CIPHER_SUITES")),
	}

	// Acme specific environment variables
	cfg.Acme.Enabled = os.Getenv("GATEON_ACME_ENABLED") == "true"
	cfg.Acme.Email = os.Getenv("GATEON_ACME_EMAIL")
	cfg.Acme.CAServer = os.Getenv("GATEON_ACME_CA_SERVER")
	cfg.Acme.ChallengeType = os.Getenv("GATEON_ACME_CHALLENGE_TYPE")

	if cfg.Acme.Email == "" {
		cfg.Acme.Email = cfg.Email
	}

	if !cfg.Acme.Enabled && os.Getenv("GATEON_ACME_ENABLED") == "" && cfg.Acme.Email != "" {
		cfg.Acme.Enabled = true
	}

	if certsEnv := os.Getenv("GATEON_TLS_CERTS"); certsEnv != "" {
		for _, pair := range strings.Split(certsEnv, ";") {
			parts := strings.Split(pair, ",")
			if len(parts) >= 2 {
				cc := CertificateConfig{
					CertFile: strings.TrimSpace(parts[0]),
					KeyFile:  strings.TrimSpace(parts[1]),
				}
				if len(parts) >= 3 {
					cc.CaFile = strings.TrimSpace(parts[2])
				}
				cfg.Certificates = append(cfg.Certificates, cc)
			}
		}
	}

	return cfg
}

func splitAndTrim(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var res []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			res = append(res, trimmed)
		}
	}
	return res
}
