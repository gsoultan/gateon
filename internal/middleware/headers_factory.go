// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"net/http"
	"strconv"
	"strings"
)

func (f *Factory) createHeaders(cfg map[string]string) (Middleware, error) {
	stsSeconds, _ := strconv.Atoi(cfg["sts_seconds"])
	stsIncludeSubdomains := parseBoolStrict(cfg["sts_include_subdomains"], false)
	stsPreload := parseBoolStrict(cfg["sts_preload"], false)
	forceSTSHeader := parseBoolStrict(cfg["force_sts_header"], false)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for k, v := range cfg {
				if strings.HasPrefix(k, "add_request_") {
					r.Header.Add(strings.TrimPrefix(k, "add_request_"), v)
				} else if strings.HasPrefix(k, "set_request_") {
					r.Header.Set(strings.TrimPrefix(k, "set_request_"), v)
				} else if strings.HasPrefix(k, "del_request_") {
					r.Header.Del(strings.TrimPrefix(k, "del_request_"))
				}
			}

			sw := &StatusResponseWriter{ResponseWriter: w, Status: http.StatusOK}
			for k, v := range cfg {
				if strings.HasPrefix(k, "add_response_") {
					sw.Header().Add(strings.TrimPrefix(k, "add_response_"), v)
				} else if strings.HasPrefix(k, "set_response_") {
					sw.Header().Set(strings.TrimPrefix(k, "set_response_"), v)
				} else if strings.HasPrefix(k, "del_response_") {
					sw.Header().Del(strings.TrimPrefix(k, "del_response_"))
				}
			}
			next.ServeHTTP(sw, r)

			if stsSeconds > 0 && (r.TLS != nil || forceSTSHeader) {
				val := "max-age=" + strconv.Itoa(stsSeconds)
				if stsIncludeSubdomains {
					val += "; includeSubDomains"
				}
				if stsPreload {
					val += "; preload"
				}
				w.Header().Set("Strict-Transport-Security", val)
			}
		})
	}, nil
}
