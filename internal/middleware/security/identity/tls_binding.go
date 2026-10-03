// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/gsoultan/gateon/internal/middleware/kind"
)

// TLS binding ties a session cookie to the client certificate of the
// connection it was issued on, so a cookie lifted from one client cannot be
// replayed by another (ADR 0046). It is RFC 8705's certificate-bound token,
// applied to the cookie a backend issues.
//
//   - Issue. When the backend's response sets the session cookie on a
//     connection that presented a client certificate, the gateway adds
//     <cookie>_binding = HMAC(secret, cookie name, SHA-256 of the certificate,
//     session value), with the session cookie's path, domain and lifetime.
//     When the backend expires the session, the binding is expired with it.
//   - Check. A request carrying the session cookie must come over TLS with a
//     client certificate and carry the binding that certificate and session
//     produce. A request with no session cookie -- the sign-in page, a public
//     asset -- is not checked.
//
// The binding is to the certificate, not to the connection. It used to be an
// HMAC keyed by the connection's TLS exporter, which no session can survive: a
// browser opens new connections whenever it likes. And nothing issued it, so
// every TLS request with a session cookie was refused, while over plain HTTP
// the middleware did nothing at all. A client proves it holds the
// certificate's key in every handshake, so the certificate is what a stolen
// cookie cannot bring along; whether a CA vouches for it is the entrypoint's
// client-authentication setting, not this middleware's question.
//
// The secret keys the HMAC. Every gateway that serves the route must share it,
// and changing it ends every bound session, which is what rotating it is for.

// minTLSBindingSecret is the shortest secret accepted: 256 bits, the HMAC's
// own strength.
const minTLSBindingSecret = 32

// tlsBindingLabel separates this HMAC's inputs from any other use of the same
// secret.
const tlsBindingLabel = "gateon tls_binding v1"

// TLSBindingConfig configures TLSBinding.
type TLSBindingConfig struct {
	CookieName string // the backend's session cookie; default "session"
	Secret     []byte // the HMAC key, at least 32 bytes
}

// NewTLSBinding builds a tls_binding middleware from a middleware config.
func NewTLSBinding(cfg map[string]string) (kind.Middleware, error) {
	c := TLSBindingConfig{CookieName: strings.TrimSpace(cfg["cookie_name"]), Secret: []byte(cfg["secret"])}
	if c.CookieName == "" {
		c.CookieName = "session"
	}
	if len(c.Secret) < minTLSBindingSecret {
		return nil, kind.CfgError("secret", "", errors.New("tls_binding needs a secret of at least 32 bytes: "+
			"the binding cookie is an HMAC under it, and every gateway serving the route must share it"))
	}
	return TLSBinding(c), nil
}

// TLSBinding returns the middleware; see the comment above for the design.
func TLSBinding(cfg TLSBindingConfig) kind.Middleware {
	b := tlsBinder{cookie: cfg.CookieName, binding: cfg.CookieName + "_binding", secret: cfg.Secret}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b.serve(next, w, r)
		})
	}
}

type tlsBinder struct {
	cookie  string
	binding string
	secret  []byte
}

func (b tlsBinder) serve(next http.Handler, w http.ResponseWriter, r *http.Request) {
	cert := clientCertificateHash(r)
	if session, err := r.Cookie(b.cookie); err == nil {
		if reason := b.refusal(r, cert, session.Value); reason != "" {
			refuseBinding(w, r, reason)
			return
		}
	}
	if cert == nil {
		// Nothing to bind a session issued here to; the next request that
		// carries it is refused above.
		next.ServeHTTP(w, r)
		return
	}
	bw := &bindingWriter{ResponseWriter: w, binder: b, cert: cert}
	next.ServeHTTP(bw, r)
	bw.commit()
}

// refusal says why a request presenting session must be refused, or "".
func (b tlsBinder) refusal(r *http.Request, cert []byte, session string) string {
	if cert == nil {
		return "Session cookie presented without a client certificate; the session is bound to the " +
			"certificate it was issued to"
	}
	got, err := r.Cookie(b.binding)
	if err != nil {
		return "Session cookie presented with no binding cookie; a session must be bound on the " +
			"connection that issued it"
	}
	// Constant time: the comparison is against a value derived from a secret
	// the client is trying to guess.
	if !hmac.Equal([]byte(got.Value), []byte(b.mac(cert, session))) {
		return "Session cookie presented with a binding for another client certificate (binding mismatch)"
	}
	return ""
}

// mac is the binding of session to the certificate whose SHA-256 is cert.
func (b tlsBinder) mac(cert []byte, session string) string {
	h := hmac.New(sha256.New, b.secret)
	h.Write([]byte(tlsBindingLabel))
	h.Write([]byte{0})
	h.Write([]byte(b.cookie))
	h.Write([]byte{0})
	h.Write(cert)
	h.Write([]byte(session))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// clientCertificateHash is the SHA-256 of the client certificate the request's
// TLS connection presented, or nil when there is none.
func clientCertificateHash(r *http.Request) []byte {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	return sum[:]
}

// bindingWriter adds the binding cookie to a response that sets or expires the
// session cookie, when the response is committed.
type bindingWriter struct {
	http.ResponseWriter
	binder    tlsBinder
	cert      []byte
	committed bool
}

func (w *bindingWriter) commit() {
	if w.committed {
		return
	}
	w.committed = true
	h := w.Header()
	for _, line := range h.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		if err != nil || c.Name != w.binder.cookie {
			continue
		}
		h.Add("Set-Cookie", w.binder.bindingCookie(c, w.cert).String())
	}
}

// bindingCookie is the binding for the session cookie the backend set: the
// same scope and lifetime, and expired when the session is.
func (b tlsBinder) bindingCookie(session *http.Cookie, cert []byte) *http.Cookie {
	// The binding travels wherever the session does, so it takes the
	// session's SameSite (a session set SameSite=None for cross-site use would
	// otherwise arrive without its binding and be refused); Lax when the
	// session names none.
	sameSite := session.SameSite
	if sameSite == http.SameSiteDefaultMode {
		sameSite = http.SameSiteLaxMode
	}
	// #nosec G124 -- HttpOnly and Secure are always set; SameSite follows the session it binds, see above.
	c := &http.Cookie{
		Name: b.binding, Path: session.Path, Domain: session.Domain,
		MaxAge: session.MaxAge, Expires: session.Expires,
		HttpOnly: true, Secure: true, SameSite: sameSite,
	}
	if session.Value == "" || session.MaxAge < 0 {
		c.MaxAge = -1
		return c
	}
	c.Value = b.mac(cert, session.Value)
	return c
}

func (w *bindingWriter) WriteHeader(code int) {
	// An informational response is not the response; its headers go out on
	// their own and the final ones are still being assembled.
	if code >= http.StatusOK {
		w.commit()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *bindingWriter) Write(p []byte) (int, error) {
	w.commit()
	return w.ResponseWriter.Write(p)
}

// Flush commits first, since flushing is what puts the headers on the wire.
func (w *bindingWriter) Flush() {
	w.commit()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *bindingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack forwards to the underlying writer, for WebSocket upgrades.
func (w *bindingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		w.committed = true
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
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
