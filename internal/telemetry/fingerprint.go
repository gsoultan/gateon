package telemetry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
)

type telemetryContextKey string

const (
	fingerprintCtxKey telemetryContextKey = "fingerprint"
	ja4hCtxKey        telemetryContextKey = "ja4h"
)

var (
	builderPool = sync.Pool{
		New: func() any {
			return &strings.Builder{}
		},
	}
)

// ClientFingerprint represents a stable identifier for a client based on various attributes.
type ClientFingerprint struct {
	Hash       string
	Attributes map[string]string
}

// GetDetailedFingerprint returns the detailed fingerprint from context or calculates it if missing.
func GetDetailedFingerprint(r *http.Request) *ClientFingerprint {
	if fp, ok := r.Context().Value(fingerprintCtxKey).(*ClientFingerprint); ok {
		return fp
	}
	return GenerateFingerprint(r)
}

// GetCachedJA4H returns the JA4H fingerprint from context or calculates it if missing.
func GetCachedJA4H(r *http.Request) string {
	if ja4h, ok := r.Context().Value(ja4hCtxKey).(string); ok {
		return ja4h
	}
	return GenerateJA4H(r)
}

// WithFingerprint adds the fingerprint and JA4H to the request context.
func WithFingerprint(r *http.Request) *http.Request {
	fp := GenerateFingerprint(r)
	ja4h := GenerateJA4H(r)
	ctx := context.WithValue(r.Context(), fingerprintCtxKey, fp)
	ctx = context.WithValue(ctx, ja4hCtxKey, ja4h)
	return r.WithContext(ctx)
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

	sb := builderPool.Get().(*strings.Builder)
	sb.Reset()
	defer builderPool.Put(sb)

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
		Hash:       hex.EncodeToString(hash[:]),
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
	headers := slices.Sorted(maps.Keys(r.Header))

	// For now, let's just hash the keys.
	h := sha256.New()
	for _, k := range headers {
		if k == "Cookie" || k == "Referer" {
			continue
		}
		h.Write([]byte(k))
		h.Write([]byte(","))
	}
	headerHash := hex.EncodeToString(h.Sum(nil))[:12]

	return fmt.Sprintf("%s%s%s%s%02d%s", methodChar, versionChar, cookieChar, refererChar, headerCount, headerHash)
}
