// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/gsoultan/gateon/internal/mgmtaddr"
)

// outboundTransport is the transport for a call a route middleware makes to a
// URL an operator configured -- a forward-auth service, an introspection
// endpoint. Its dialer refuses the gateway's own management listener, as the
// proxy's does (ADR 0052): these clients dialled with http.DefaultTransport,
// so an auth URL naming 127.0.0.1:<management port> reached the management
// API from loopback, and forward auth hands a non-2xx response body straight
// back to the client.
func outboundTransport(insecureSkipVerify bool) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   mgmtaddr.Control,
	}).DialContext
	if insecureSkipVerify {
		// #nosec G402 -- only when the operator sets tls_insecure_skip_verify on
		// this specific middleware, for a service presenting an internal or
		// self-signed certificate; the zero value keeps verification on.
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return t
}
