package middleware

import (
	"strconv"
	"strings"
)

func (f *Factory) createForwardAuth(cfg map[string]string) (Middleware, error) {
	maxBody := int64(1024 * 1024)
	if v := cfg["max_body_size"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			maxBody = n
		}
	}
	forwardCfg := ForwardAuthConfig{
		Address:               strings.TrimSpace(cfg["address"]),
		TrustForwardHeader:    parseBool(cfg["trust_forward_header"], false),
		AuthResponseHeaders:   parseListStrict(cfg["auth_response_headers"]),
		AuthRequestHeaders:    parseListStrict(cfg["auth_request_headers"]),
		ForwardBody:           parseBool(cfg["forward_body"], false),
		PreserveRequestMethod: parseBool(cfg["preserve_request_method"], false),
		MaxBodySize:           maxBody,
		TLSInsecureSkipVerify: parseBool(cfg["tls_insecure_skip_verify"], false),
	}
	return ForwardAuth(forwardCfg)
}
