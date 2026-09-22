// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http"

	"github.com/gsoultan/gateon/internal/middleware/kind"
)

// tlsBindingExporterLabel is the RFC 9266 "tls-exporter" channel binding
// label. TLS 1.3 removed tls-unique; the exporter is its replacement, and
// using the registered label rather than an invented one keeps the value
// meaningful to anything that later needs to derive the same binding.
const tlsBindingExporterLabel = "EXPORTER-Channel-Binding"

// channelBinding returns material that is unique to this TLS connection, or
// nil when the connection cannot provide any.
//
// Two mechanisms, because one does not cover the deployment. TLSUnique is
// what this middleware used exclusively, and Go sets it to nil for every
// TLS 1.3 connection and every resumed one -- so against a modern client the
// binding check did nothing at all, silently, while the dashboard showed the
// feature enabled. Nothing in this tree pins MaxVersion below 1.3, so that
// was the common case rather than the edge.
func channelBinding(cs *tls.ConnectionState) []byte {
	if cs == nil || !cs.HandshakeComplete {
		// ExportKeyingMaterial is only meaningful once the handshake has
		// finished, and on a ConnectionState that did not come from a real
		// connection its internal export function is not set at all.
		return nil
	}
	if cs.Version >= tls.VersionTLS13 {
		// 32 bytes is what RFC 9266 specifies for tls-exporter.
		material, err := cs.ExportKeyingMaterial(tlsBindingExporterLabel, nil, 32)
		if err != nil {
			return nil
		}
		return material
	}
	if len(cs.TLSUnique) > 0 {
		return cs.TLSUnique
	}
	return nil
}

// TlsBinding cryptographically binds a session cookie to the TLS connection,
// so a cookie lifted from one connection cannot be replayed on another.
//
// The binding cookie is never minted for a request that did not already have
// one. That is how this middleware used to work -- a session cookie with no
// binding got a binding computed for whatever connection presented it -- and
// it made the middleware permit precisely the attack its own error message
// names. An attacker with a stolen session cookie only had to omit the
// binding cookie to be handed a valid one.
//
// So the binding must be established by whatever issues the session, on the
// connection that issues it. A session cookie arriving here without a binding
// is either replayed or predates the feature being enabled, and both are
// refused: an operator who turns on TLS binding is asking for the binding to
// be enforced, and a control that mints credentials for anyone who asks is
// not a control.
func TlsBinding(cookieName string) kind.Middleware {
	bindingCookieName := cookieName + "_binding"

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			binding := channelBinding(r.TLS)
			if binding == nil {
				// No TLS, or a connection that can supply no channel binding
				// (TLS terminated upstream). There is nothing to bind to, and
				// refusing here would break every plaintext-to-gateway
				// deployment, so this passes through -- the middleware simply
				// cannot apply.
				next.ServeHTTP(w, r)
				return
			}

			sessionCookie, err := r.Cookie(cookieName)
			if err != nil {
				// No session to bind.
				next.ServeHTTP(w, r)
				return
			}

			h := hmac.New(sha256.New, binding)
			h.Write([]byte(sessionCookie.Value))
			expectedBinding := hex.EncodeToString(h.Sum(nil))

			bindingCookie, err := r.Cookie(bindingCookieName)
			if err != nil {
				refuseBinding(w, r,
					"Session cookie presented with no binding cookie; a session "+
						"must be bound on the connection that issued it")
				return
			}

			// Constant time: the comparison is against a value derived from a
			// secret the client is trying to guess.
			if !hmac.Equal([]byte(bindingCookie.Value), []byte(expectedBinding)) {
				refuseBinding(w, r,
					"Session cookie presented from a different TLS connection (binding mismatch)")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func refuseBinding(w http.ResponseWriter, r *http.Request, details string) {
	kind.RecordThreat(r, kind.Threat{
		Type:        "tls_binding_mismatch",
		Score:       80,
		Details:     details,
		Category:    "auth",
		Severity:    kind.SeverityHigh,
		ActionTaken: kind.ActionBlocked,
	})
	http.Error(w, "Security Check Failed: Session binding mismatch", http.StatusForbidden)
}
