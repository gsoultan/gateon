package telemetry

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
)

type telemetryContextKey string

const (
	fingerprintCtxKey telemetryContextKey = "fingerprint"
	ja4hCtxKey        telemetryContextKey = "ja4h"
)

var (
	hashPool = sync.Pool{
		New: func() any {
			return sha256.New()
		},
	}
	builderPool = sync.Pool{
		New: func() any {
			return &strings.Builder{}
		},
	}
	headerKeysPool = sync.Pool{
		New: func() any {
			return make([]string, 0, 32)
		},
	}
	fingerprintPool = sync.Pool{
		New: func() any {
			return &ClientFingerprint{
				Attributes: make(map[string]string, 16),
			}
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

// GetFingerprintHash returns only the fingerprint hash.
func GetFingerprintHash(r *http.Request) string {
	if fp, ok := r.Context().Value(fingerprintCtxKey).(*ClientFingerprint); ok {
		return fp.Hash
	}

	h := hashPool.Get().(hash.Hash)
	h.Reset()
	defer hashPool.Put(h)

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

	for _, k := range stableHeaders {
		val := r.Header.Get(k)
		if val != "" {
			io.WriteString(h, k)
			io.WriteString(h, ":")
			io.WriteString(h, val)
			io.WriteString(h, "|")
		}
	}

	if r.TLS != nil {
		// Use manual byte writing instead of fmt.Fprintf
		var b [16]byte
		binary.BigEndian.PutUint16(b[0:], r.TLS.Version)
		binary.BigEndian.PutUint16(b[2:], r.TLS.CipherSuite)
		h.Write([]byte("tls:"))
		h.Write(b[:4])
		h.Write([]byte("|"))
	}

	if r.Proto != "" {
		h.Write([]byte("proto:"))
		h.Write([]byte(r.Proto))
		h.Write([]byte("|"))
	}

	sum := h.Sum(nil)
	return hex.EncodeToString(sum)
}

// GenerateFingerprint creates a hash of client attributes to identify the actor.
func GenerateFingerprint(r *http.Request) *ClientFingerprint {
	fp := fingerprintPool.Get().(*ClientFingerprint)
	clear(fp.Attributes)

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

	h := hashPool.Get().(hash.Hash)
	h.Reset()
	defer hashPool.Put(h)

	for _, k := range stableHeaders {
		val := r.Header.Get(k)
		if val != "" {
			fp.Attributes[k] = val
			io.WriteString(h, k)
			io.WriteString(h, ":")
			io.WriteString(h, val)
			io.WriteString(h, "|")
		}
	}

	// 2. TLS properties (if available)
	if r.TLS != nil {
		v := strconv.FormatUint(uint64(r.TLS.Version), 16)
		c := strconv.FormatUint(uint64(r.TLS.CipherSuite), 16)
		fp.Attributes["tls_version"] = v
		fp.Attributes["cipher_suite"] = c
		io.WriteString(h, "tls:")
		io.WriteString(h, v)
		io.WriteString(h, ":")
		io.WriteString(h, c)
		io.WriteString(h, "|")
	}

	// 3. Negotiated Protocol
	if r.Proto != "" {
		fp.Attributes["proto"] = r.Proto
		io.WriteString(h, "proto:")
		io.WriteString(h, r.Proto)
		io.WriteString(h, "|")
	}

	sum := h.Sum(nil)
	fp.Hash = hex.EncodeToString(sum)

	return fp
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
	headerKeys := headerKeysPool.Get().([]string)
	headerKeys = headerKeys[:0]
	for k := range r.Header {
		headerKeys = append(headerKeys, k)
	}
	slices.Sort(headerKeys)
	defer func() {
		if cap(headerKeys) <= 128 {
			headerKeysPool.Put(headerKeys)
		}
	}()

	h := hashPool.Get().(hash.Hash)
	h.Reset()
	defer hashPool.Put(h)

	for _, k := range headerKeys {
		if k == "Cookie" || k == "Referer" {
			continue
		}
		io.WriteString(h, k)
		io.WriteString(h, ",")
	}
	headerHash := hex.EncodeToString(h.Sum(nil))[:12]

	// method(1) + version(1) + cookie(1) + referer(1) + count(2) + hash(12) = 18 chars
	var buf [18]byte
	buf[0] = methodChar[0]
	buf[1] = versionChar[0]
	buf[2] = cookieChar[0]
	buf[3] = refererChar[0]
	if headerCount < 10 {
		buf[4] = '0'
		buf[5] = byte('0' + headerCount)
	} else if headerCount < 100 {
		buf[4] = byte('0' + headerCount/10)
		buf[5] = byte('0' + headerCount%10)
	} else {
		buf[4] = '9'
		buf[5] = '9'
	}
	copy(buf[6:], headerHash)

	return string(buf[:])
}
