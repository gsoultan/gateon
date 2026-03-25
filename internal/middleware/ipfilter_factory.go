package middleware

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/request"
)

func (f *Factory) createIPFilter(cfg map[string]string) (Middleware, error) {
	allowList := parseListStrict(cfg["allow_list"])
	denyList := parseListStrict(cfg["deny_list"])
	trust := request.ParseTrustCloudflare(cfg["trust_cloudflare_headers"])
	clientIP := func(r *http.Request) string { return request.GetClientIP(r, trust) }
	return IPFilterWithClientIP(allowList, denyList, clientIP), nil
}
