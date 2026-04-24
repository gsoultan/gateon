package telemetry

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
)

// ClientFingerprint represents a stable identifier for a client based on various attributes.
type ClientFingerprint struct {
	Hash       string
	Attributes map[string]string
}

// GenerateFingerprint creates a hash of client attributes to identify the actor.
func GenerateFingerprint(r *http.Request) *ClientFingerprint {
	attrs := make(map[string]string)

	// 1. Headers (using a stable subset)
	stableHeaders := []string{
		"User-Agent",
		"Accept-Language",
		"Accept-Encoding",
		"DNT",
		"Upgrade-Insecure-Requests",
		"Sec-CH-UA",
		"Sec-CH-UA-Mobile",
		"Sec-CH-UA-Platform",
	}

	var sb strings.Builder
	for _, h := range stableHeaders {
		val := r.Header.Get(h)
		if val != "" {
			attrs[h] = val
			sb.WriteString(h + ":" + val + "|")
		}
	}

	// 2. TLS properties (if available)
	if r.TLS != nil {
		attrs["tls_version"] = fmt.Sprintf("%x", r.TLS.Version)
		attrs["cipher_suite"] = fmt.Sprintf("%x", r.TLS.CipherSuite)
		sb.WriteString(fmt.Sprintf("tls:%x:%x|", r.TLS.Version, r.TLS.CipherSuite))
	}

	// 3. Negotiated Protocol
	if r.Proto != "" {
		attrs["proto"] = r.Proto
		sb.WriteString("proto:" + r.Proto + "|")
	}

	hash := sha256.Sum256([]byte(sb.String()))

	return &ClientFingerprint{
		Hash:       fmt.Sprintf("%x", hash),
		Attributes: attrs,
	}
}

// TrackBehavior stores and analyzes sequences of requests from a fingerprint.
// This is a stub for the "Normal Usage Profiles" requirement.
func TrackBehavior(fingerprint string, path string) {
	// In a real implementation, this would update a Redis/DB store with:
	// - Path sequence (e.g., /login -> /dashboard -> /profile)
	// - Timing between requests
	// - Unusual spikes in specific sequences
}
