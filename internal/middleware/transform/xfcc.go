// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/gsoultan/gateon/internal/middleware/kind"
)

// XFCCConfig configures the X-Forwarded-Client-Cert middleware.
type XFCCConfig struct {
	ForwardBy bool `json:"forward_by"`
	// By is the identity By= names: in Envoy's terms the URI SAN of the
	// gateway's own certificate. The operator states it, because a middleware
	// cannot learn which of the gateway's certificates served a connection --
	// crypto/tls reports only the peer's -- and an entrypoint may serve many.
	By             string `json:"by"`
	ForwardHash    bool   `json:"forward_hash"`
	ForwardSubject bool   `json:"forward_subject"`
	ForwardURI     bool   `json:"forward_uri"`
	ForwardDNS     bool   `json:"forward_dns"`
}

// XFCC returns a middleware that extracts client certificate details and propagates them via X-Forwarded-Client-Cert header.
func XFCC(cfg XFCCConfig) kind.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Never trust a client-supplied X-Forwarded-Client-Cert: the gateway
			// is the sole authority for this header. Strip any inbound value
			// unconditionally before doing anything else, so a request that
			// arrives without a verified client cert can never inject identity.
			r.Header.Del("X-Forwarded-Client-Cert")

			// No verified peer certificate means there is no identity to
			// forward -- and the inbound header is already gone, so the
			// upstream sees absence rather than a claim.
			if kind.IsCorsPreflight(r) || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			if v := xfccHeader(cfg, r.TLS.PeerCertificates[0]); v != "" {
				// Set only the gateway-derived value; do not concatenate any
				// (already-stripped) inbound header.
				r.Header.Set("X-Forwarded-Client-Cert", v)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// xfccHeader builds the Envoy-format X-Forwarded-Client-Cert value for a
// verified peer certificate, or "" if the config asks for nothing this
// certificate can supply.
//
// It is a pure function of (config, certificate) so the branches below sit at
// one level instead of three: gocognit charges a branch by its depth, and a
// middleware is two closures deep before it reads a single field.
//
// Pairs come in Envoy's order (By, Hash, Subject, URI, DNS). Every value from
// the certificate goes through xfccPair, which quotes and escapes it: they were
// written raw, so a certificate whose URI SAN read "spiffe://a;Hash=x" added a
// Hash pair of its holder's choosing (ADR 0046).
func xfccHeader(cfg XFCCConfig, cert *x509.Certificate) string {
	var b strings.Builder
	if cfg.ForwardBy && cfg.By != "" {
		xfccPair(&b, "By", cfg.By, false)
	}
	if cfg.ForwardHash {
		// Envoy defines Hash as the SHA-256 of the DER certificate, which
		// is what upstreams pin against. cert.Signature is the issuer's
		// signature over the certificate — a different value entirely.
		sum := sha256.Sum256(cert.Raw)
		xfccPair(&b, "Hash", hex.EncodeToString(sum[:]), false)
	}
	if cfg.ForwardSubject {
		// Envoy always quotes the subject.
		xfccPair(&b, "Subject", cert.Subject.String(), true)
	}
	if cfg.ForwardURI && len(cert.URIs) > 0 {
		xfccPair(&b, "URI", cert.URIs[0].String(), false)
	}
	if cfg.ForwardDNS && len(cert.DNSNames) > 0 {
		xfccPair(&b, "DNS", cert.DNSNames[0], false)
	}
	return b.String()
}

// xfccSpecial are the characters that make an XFCC value need quotes: the
// element and pair separators, '=', the quote and its escape, and space.
const xfccSpecial = ",;=\"\\ "

// xfccPair appends key=value to b, after a ';' when b is not empty.
//
// A value holding any of xfccSpecial, or a control character, is
// double-quoted, with '"' and '\' escaped by a backslash: Envoy's format
// escapes the quote, and escaping the backslash too keeps a value that ends in
// one from escaping the closing quote. A control character, which no header
// may carry, is written as %XX.
func xfccPair(b *strings.Builder, key, value string, alwaysQuote bool) {
	if b.Len() > 0 {
		b.WriteByte(';')
	}
	b.WriteString(key)
	b.WriteByte('=')
	if !alwaysQuote && !xfccNeedsQuotes(value) {
		b.WriteString(value)
		return
	}
	b.WriteByte('"')
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case isControl(c):
			fmt.Fprintf(b, "%%%02X", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
}

func xfccNeedsQuotes(v string) bool {
	if strings.ContainsAny(v, xfccSpecial) {
		return true
	}
	for i := 0; i < len(v); i++ {
		if isControl(v[i]) {
			return true
		}
	}
	return false
}

func isControl(c byte) bool { return c < 0x20 || c == 0x7f }
