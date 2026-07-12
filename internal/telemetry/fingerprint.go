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
	"strings"
	"sync"

	"github.com/gsoultan/gateon/internal/request"
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
	if rs := request.GetRequestState(r); rs != nil {
		if fp, ok := rs.Fingerprint.(*ClientFingerprint); ok {
			return fp
		}
		fp := GenerateFingerprint(r)
		rs.Fingerprint = fp
		return fp
	}
	if fp, ok := r.Context().Value(fingerprintCtxKey).(*ClientFingerprint); ok {
		return fp
	}
	return GenerateFingerprint(r)
}

// GetCachedJA4H returns the JA4H fingerprint from context or calculates it if missing.
func GetCachedJA4H(r *http.Request) string {
	if rs := request.GetRequestState(r); rs != nil {
		if rs.JA4H != "" {
			return rs.JA4H
		}
		ja4h := GenerateJA4H(r)
		rs.JA4H = ja4h
		return ja4h
	}
	if ja4h, ok := r.Context().Value(ja4hCtxKey).(string); ok {
		return ja4h
	}
	return GenerateJA4H(r)
}

// WithFingerprint adds the fingerprint and JA4H to the request context.
func WithFingerprint(r *http.Request) *http.Request {
	fp := GenerateFingerprint(r)
	ja4h := GenerateJA4H(r)
	if rs := request.GetRequestState(r); rs != nil {
		rs.Fingerprint = fp
		rs.JA4H = ja4h
		return r
	}
	ctx := context.WithValue(r.Context(), fingerprintCtxKey, fp)
	ctx = context.WithValue(ctx, ja4hCtxKey, ja4h)
	return r.WithContext(ctx)
}

// GetFingerprintHash returns only the fingerprint hash.
func GetFingerprintHash(r *http.Request) string {
	if rs := request.GetRequestState(r); rs != nil {
		if fp, ok := rs.Fingerprint.(*ClientFingerprint); ok {
			return fp.Hash
		}
		// If detailed fp not present, we might still have just the hash if we optimize it later.
		// For now, compute it.
	}
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
			h.Write([]byte(k))
			h.Write([]byte{':'})
			h.Write([]byte(val))
			h.Write([]byte{'|'})
		}
	}

	// 2. TLS properties (if available)
	if r.TLS != nil {
		var buf [16]byte
		v := hex.EncodeToString(binary.BigEndian.AppendUint16(buf[:0], r.TLS.Version))
		c := hex.EncodeToString(binary.BigEndian.AppendUint16(buf[:0], r.TLS.CipherSuite))
		fp.Attributes["tls_version"] = v
		fp.Attributes["cipher_suite"] = c
		h.Write([]byte("tls:"))
		h.Write([]byte(v))
		h.Write([]byte{':'})
		h.Write([]byte(c))
		h.Write([]byte{'|'})
	}

	// 3. Negotiated Protocol
	if r.Proto != "" {
		fp.Attributes["proto"] = r.Proto
		h.Write([]byte("proto:"))
		h.Write([]byte(r.Proto))
		h.Write([]byte{'|'})
	}

	sum := h.Sum(nil)
	fp.Hash = hex.EncodeToString(sum)

	return fp
}

// GenerateJA4H generates a JA4H HTTP fingerprint.
// Format: [method(1)][version(1)][cookie(1)][referer(1)][header_count(2)][header_hash(12)]
func GenerateJA4H(r *http.Request) string {
	methodChar := byte('o') // other
	switch r.Method {
	case "GET":
		methodChar = 'g'
	case "POST":
		methodChar = 'p'
	}

	versionChar := byte('2')
	if strings.Contains(r.Proto, "1.1") {
		versionChar = '1'
	} else if strings.Contains(r.Proto, "3") {
		versionChar = '3'
	}

	cookieChar := byte('n')
	if r.Header.Get("Cookie") != "" {
		cookieChar = 'c'
	}

	refererChar := byte('n')
	if r.Header.Get("Referer") != "" {
		refererChar = 'r'
	}

	headerCount := len(r.Header)

	// Optimized header stable hashing
	h := hashPool.Get().(hash.Hash)
	h.Reset()

	// Collect keys into a local buffer if small enough
	var localKeys [32]string
	keys := localKeys[:0]
	for k := range r.Header {
		if k != "Cookie" && k != "Referer" {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{','})
	}
	headerHashBytes := h.Sum(nil)
	headerHash := hex.EncodeToString(headerHashBytes)[:12]

	hashPool.Put(h)

	// method(1) + version(1) + cookie(1) + referer(1) + count(2) + hash(12) = 18 chars
	var buf [18]byte
	buf[0] = methodChar
	buf[1] = versionChar
	buf[2] = cookieChar
	buf[3] = refererChar
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
