package middleware

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// XFCCConfig configures the X-Forwarded-Client-Cert middleware.
type XFCCConfig struct {
	ForwardBy      bool `json:"forward_by"`
	ForwardHash    bool `json:"forward_hash"`
	ForwardSubject bool `json:"forward_subject"`
	ForwardURI     bool `json:"forward_uri"`
	ForwardDNS     bool `json:"forward_dns"`
}

// XFCC returns a middleware that extracts client certificate details and propagates them via X-Forwarded-Client-Cert header.
func XFCC(cfg XFCCConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Never trust a client-supplied X-Forwarded-Client-Cert: the gateway
			// is the sole authority for this header. Strip any inbound value
			// unconditionally before doing anything else, so a request that
			// arrives without a verified client cert can never inject identity.
			r.Header.Del("X-Forwarded-Client-Cert")

			if IsCorsPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			cert := r.TLS.PeerCertificates[0]
			var parts []string

			// Hash is always useful
			if cfg.ForwardHash {
				// Envoy uses SHA256 of the DER
				parts = append(parts, fmt.Sprintf("Hash=%s", hex.EncodeToString(cert.Signature)))
			}

			if cfg.ForwardSubject {
				parts = append(parts, fmt.Sprintf("Subject=%q", cert.Subject.String()))
			}

			if cfg.ForwardURI && len(cert.URIs) > 0 {
				parts = append(parts, fmt.Sprintf("URI=%s", cert.URIs[0].String()))
			}

			if cfg.ForwardDNS && len(cert.DNSNames) > 0 {
				parts = append(parts, fmt.Sprintf("DNS=%s", cert.DNSNames[0]))
			}

			if len(parts) > 0 {
				// Set only the gateway-derived value; do not concatenate any
				// (already-stripped) inbound header.
				r.Header.Set("X-Forwarded-Client-Cert", strings.Join(parts, ";"))
			}

			next.ServeHTTP(w, r)
		})
	}
}
