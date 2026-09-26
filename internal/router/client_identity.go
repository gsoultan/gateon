// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/middleware"
)

// clientIdentityChooser is a handler that chooses the client certificate it
// presents to a backend from request headers: a proxy.ProxyHandler whose
// service selects its identities BY_HEADER.
type clientIdentityChooser interface {
	ClientIdentityHeaders() []string
}

// clientIdentityGuard removes a client's copies of the headers h chooses a
// backend client certificate by, before any of the route's own middlewares
// run. It returns nil when h chooses by none.
//
// Those headers are the gateway's to set. While a client could send one, it
// named the identity the gateway authenticated to the backend as: "X-Tenant:
// admin" was enough, on a route with nothing on it that ever set X-Tenant.
// Now only the route's middlewares can choose -- a claim mapping,
// forward-auth's response headers, a headers rule -- which is the contract a
// mapped claim header already has. See ADR-0014.
func clientIdentityGuard(h http.Handler) middleware.Middleware {
	chooser, ok := h.(clientIdentityChooser)
	if !ok {
		return nil
	}
	names := chooser.ClientIdentityHeaders()
	if len(names) == 0 {
		return nil
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, name := range names {
				r.Header.Del(name)
			}
			next.ServeHTTP(w, r)
		})
	}
}
