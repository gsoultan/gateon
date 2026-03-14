package middleware

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func (f *Factory) createHMAC(cfg map[string]string) (Middleware, error) {
	secret := strings.TrimSpace(cfg["secret"])
	if secret == "" {
		secret = os.Getenv("GATEON_HMAC_SECRET")
	}
	if secret == "" {
		return nil, fmt.Errorf("hmac requires secret or GATEON_HMAC_SECRET env")
	}
	header := cfg["header"]
	if header == "" {
		header = "X-Signature-256"
	}
	prefix := cfg["prefix"]
	if prefix == "" {
		prefix = "sha256="
	}
	methods := cfg["methods"]
	var methodList []string
	if methods != "" {
		for _, m := range strings.Split(methods, ",") {
			m = strings.TrimSpace(strings.ToUpper(m))
			if m != "" {
				methodList = append(methodList, m)
			}
		}
	}
	bodyLimit := int64(1024 * 1024)
	if v := cfg["body_limit"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			bodyLimit = n
		}
	}
	return HMAC(HMACConfig{
		Secret:    secret,
		Header:    header,
		Prefix:    prefix,
		Methods:   methodList,
		BodyLimit: bodyLimit,
	})
}
