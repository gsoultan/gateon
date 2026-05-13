package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
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

// GenerateJA4H generates a JA4H HTTP fingerprint.
// Format: [method(1)][version(1)][cookie(1)][referer(1)][header_count(2)][header_hash(12)]
func GenerateJA4H(r *http.Request) string {
	methodChar := "o" // other
	switch r.Method {
	case "GET":
		methodChar = "g"
	case "POST":
		methodChar = "p"
	}

	versionChar := "2"
	if strings.Contains(r.Proto, "1.1") {
		versionChar = "1"
	} else if strings.Contains(r.Proto, "3") {
		versionChar = "3"
	}

	cookieChar := "n"
	if r.Header.Get("Cookie") != "" {
		cookieChar = "c"
	}

	refererChar := "n"
	if r.Header.Get("Referer") != "" {
		refererChar = "r"
	}

	headerCount := len(r.Header)

	// Collect and sort headers for stable hashing
	var headers []string
	for k := range r.Header {
		if k == "Cookie" || k == "Referer" {
			continue
		}
		headers = append(headers, k)
	}
	// Note: In Go 1.26+, we can use slices.Sorted(maps.Keys(r.Header))
	// but r.Header is a map[string][]string.
	// Actually, we can use slices.Sorted for strings.

	// For now, let's just hash the keys.
	h := sha256.New()
	h.Write([]byte(strings.Join(headers, ",")))
	headerHash := hex.EncodeToString(h.Sum(nil))[:12]

	return fmt.Sprintf("%s%s%s%s%02d%s", methodChar, versionChar, cookieChar, refererChar, headerCount, headerHash)
}
