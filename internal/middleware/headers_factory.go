// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/request"
)

func (f *Factory) createHeaders(cfg map[string]string) (Middleware, error) {
	stsValue := hstsValue(cfg)
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

			// Before next, like the set_response_ headers above: once the
			// response has been written the header map is on the wire, and a
			// Set after it changes nothing. This used to run after next and so
			// never reached a client. request.IsSecure rather than r.TLS, which
			// is nil behind a TLS-terminating proxy.
			if stsValue != "" && (forceSTSHeader || request.IsSecure(r)) {
				sw.Header().Set("Strict-Transport-Security", stsValue)
			}
			next.ServeHTTP(sw, r)
		})
	}, nil
}

// hstsValue builds the Strict-Transport-Security value once, when the route is
// built; "" when sts_seconds is unset or not positive.
func hstsValue(cfg map[string]string) string {
	stsSeconds, _ := strconv.Atoi(cfg["sts_seconds"])
	if stsSeconds <= 0 {
		return ""
	}
	val := "max-age=" + strconv.Itoa(stsSeconds)
	if parseBoolStrict(cfg["sts_include_subdomains"], false) {
		val += "; includeSubDomains"
	}
	if parseBoolStrict(cfg["sts_preload"], false) {
		val += "; preload"
	}
	return val
}
