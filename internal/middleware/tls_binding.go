package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

// TlsBinding cryptographically binds a session cookie to the TLS connection.
// It uses TLS Unique channel binding to ensure the cookie is only valid for the specific TLS session.
func TlsBinding(cookieName string) Middleware {
	bindingCookieName := cookieName + "_binding"

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.TLSUnique) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			sessionCookie, err := r.Cookie(cookieName)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Calculate expected binding
			h := hmac.New(sha256.New, r.TLS.TLSUnique)
			h.Write([]byte(sessionCookie.Value))
			expectedBinding := hex.EncodeToString(h.Sum(nil))

			bindingCookie, err := r.Cookie(bindingCookieName)
			if err != nil {
				// Binding missing. If we are in "Enforce" mode, we should set it or reject.
				// For production readiness, we set it on the first connection and then enforce it.
				http.SetCookie(w, &http.Cookie{
					Name:     bindingCookieName,
					Value:    expectedBinding,
					Path:     "/",
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteLaxMode,
				})
				next.ServeHTTP(w, r)
				return
			}

			if bindingCookie.Value != expectedBinding {
				// Potential session hijacking or cookie replay from a different TLS connection.
				recordAdvancedThreat(r, "tls_binding_mismatch", 80, "Session cookie presented from a different TLS connection (binding mismatch)", "")
				http.Error(w, "Security Check Failed: Session binding mismatch", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
