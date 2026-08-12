// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/gsoultan/gateon/internal/request"
)

type telemetryContextKey string

const (
	fingerprintCtxKey telemetryContextKey = "fingerprint"
	ja4hCtxKey        telemetryContextKey = "ja4h"
	ja4plusCtxKey     telemetryContextKey = "ja4plus"
)

var (
	builderPool = sync.Pool{
		New: func() any {
			return &strings.Builder{}
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

// JA4FromTrustedHeader returns the JA4 fingerprint supplied by X-JA4-Fingerprint,
// but only when the immediate peer is a trusted proxy. Otherwise it returns "".
//
// The header exists so a TLS terminator in front of the gateway can pass down a
// fingerprint it computed from the handshake, which this process never sees.
// Read unconditionally it is just a string the client chose, and a
// security-relevant one: the JA4+ value keys reputation, so a caller could
// rotate the header to shed a bad score as fast as it earns one, or send
// another client's fingerprint to spoil theirs. It also reaches rendering and
// storage paths, where an arbitrary string is a liability of its own.
//
// GetClientIP already refuses to read X-Forwarded-For from an untrusted peer
// for the same reason; this header was simply skipping the rule. Gating it here
// keeps the decision in one place rather than at each of the call sites that
// used to read it raw.
func JA4FromTrustedHeader(r *http.Request) string {
	if !ja4HeaderTrusted(r.RemoteAddr) {
		return ""
	}
	return r.Header.Get("X-JA4-Fingerprint")
}

// ja4HeaderTrusted is a variable purely so the test can exercise both sides of
// the gate. request builds its trusted-proxy set in init() from the
// environment, so a test cannot change it afterwards, and a test that could
// only ever see the untrusted answer would still pass if someone "fixed" this
// by returning "" unconditionally — which would quietly disable the feature for
// the terminators that legitimately set the header. Never reassigned outside
// tests, so the request path reads a constant.
var ja4HeaderTrusted = func(remoteAddr string) bool {
	return request.IsTrusted(remoteAddr, false)
}

// GetJA4Plus returns the composite JA4+ fingerprint (JA4_JA4H).
func GetJA4Plus(r *http.Request) string {
	if rs := request.GetRequestState(r); rs != nil {
		if rs.JA4Plus != "" {
			return rs.JA4Plus
		}
		ja4 := rs.JA4
		if ja4 == "" {
			ja4 = JA4FromTrustedHeader(r)
		}
		ja4h := GetCachedJA4H(r)
		ja4plus := ja4 + "_" + ja4h
		rs.JA4Plus = ja4plus
		return ja4plus
	}
	if val, ok := r.Context().Value(ja4plusCtxKey).(string); ok {
		return val
	}
	// Manual assembly if no state
	ja4 := JA4FromTrustedHeader(r)
	ja4h := GenerateJA4H(r)
	return ja4 + "_" + ja4h
}

// WithFingerprint adds the fingerprint and JA4H to the request context.
func WithFingerprint(r *http.Request) *http.Request {
	fp := GenerateFingerprint(r)
	ja4h := GenerateJA4H(r)
	ja4 := JA4FromTrustedHeader(r)
	ja4plus := ja4 + "_" + ja4h

	if rs := request.GetRequestState(r); rs != nil {
		rs.Fingerprint = fp
		rs.JA4 = ja4
		rs.JA4H = ja4h
		rs.JA4Plus = ja4plus
		return r
	}
	ctx := context.WithValue(r.Context(), fingerprintCtxKey, fp)
	ctx = context.WithValue(ctx, ja4hCtxKey, ja4h)
	ctx = context.WithValue(ctx, ja4plusCtxKey, ja4plus)
	return r.WithContext(ctx)
}

// GetFingerprintHash returns only the fingerprint hash (JA4+).
func GetFingerprintHash(r *http.Request) string {
	return GetJA4Plus(r)
}

// GenerateFingerprint creates a JA4+ fingerprint and identifies the actor.
func GenerateFingerprint(r *http.Request) *ClientFingerprint {
	fp := fingerprintPool.Get().(*ClientFingerprint)
	clear(fp.Attributes)

	ja4plus := GetJA4Plus(r)
	fp.Hash = ja4plus
	fp.Attributes["ja4plus"] = ja4plus

	// Still populate attributes for visibility in dashboard
	if r.TLS != nil {
		var buf [16]byte
		v := hex.EncodeToString(binary.BigEndian.AppendUint16(buf[:0], r.TLS.Version))
		c := hex.EncodeToString(binary.BigEndian.AppendUint16(buf[:0], r.TLS.CipherSuite))
		fp.Attributes["tls_version"] = v
		fp.Attributes["cipher_suite"] = c
	}
	if r.Proto != "" {
		fp.Attributes["proto"] = r.Proto
	}
	fp.Attributes["user_agent"] = r.UserAgent()

	return fp
}

// GenerateJA4H generates a JA4H HTTP fingerprint.
// Format: [ja4h_a]_[ja4h_b]
// ja4h_a: [method(2)][version(2)][cookie(1)][referer(1)][header_count(2)][alpn(2)]
// ja4h_b: [header_hash(12)]
// ja4hHeaderNames are the only header names JA4H's header component considers.
// The JA4H specification hashes header *names*, not their values, and gateon
// narrows that further to the two that identify a client rather than a request.
var ja4hHeaderNames = [...]string{"Accept-Language", "User-Agent"}

// ja4hHeaderHash is every value the header component can take, indexed by a
// two-bit presence mask: bit 0 is Accept-Language, bit 1 is User-Agent.
//
// There are four. That is not an artefact of precomputing them — it is the
// honest size of this component's value space, and it matters because JA4+ is
// used as a mitigation key. A hash over two fixed names carries two bits, so
// JA4H identifies a client *class*, not a client: every browser that sends both
// headers lands on the same value. See TestJA4HHeaderHashSpace.
//
// Precomputing turns a per-request SHA-256 and four allocations into a mask and
// an index.
var ja4hHeaderHash [4]string

func init() {
	for mask := range ja4hHeaderHash {
		h := sha256.New()
		// Sorted order, which is what the previous implementation emitted:
		// Accept-Language before User-Agent.
		for i, name := range ja4hHeaderNames {
			if mask&(1<<i) == 0 {
				continue
			}
			_, _ = io.WriteString(h, name)
			_, _ = h.Write([]byte{','})
		}
		var sum [sha256.Size]byte
		var hexbuf [12]byte
		hex.Encode(hexbuf[:], h.Sum(sum[:0])[:6])
		ja4hHeaderHash[mask] = string(hexbuf[:])
	}
}

// ja4hHeaderMask reports which tracked headers are present and how many.
// Canonical-key lookups, so there is no iteration over the header map and no
// per-header lowercasing on the request path.
func ja4hHeaderMask(h http.Header) (mask, count int) {
	for i, name := range ja4hHeaderNames {
		if _, ok := h[name]; ok {
			mask |= 1 << i
			count++
		}
	}
	return mask, count
}

// lowerASCII2 folds the first two bytes of s to lower case without allocating.
// HTTP methods are ASCII tokens by RFC 9110, so a byte-wise fold is exact.
func lowerASCII2(s string) (byte, byte) {
	lo := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + ('a' - 'A')
		}
		return b
	}
	switch len(s) {
	case 0:
		return 'o', '0'
	case 1:
		return lo(s[0]), '0'
	default:
		return lo(s[0]), lo(s[1])
	}
}

// GenerateJA4H builds the JA4H fingerprint. Allocation-free apart from the
// returned string, which is assembled in one pass rather than concatenated.
func GenerateJA4H(r *http.Request) string {
	m0, m1 := lowerASCII2(r.Method)

	var v0, v1 byte = '1', '1'
	switch {
	case r.ProtoMajor == 2:
		v0, v1 = '2', '0'
	case r.ProtoMajor == 3:
		v0, v1 = '3', '0'
	case r.ProtoMajor == 1 && r.ProtoMinor == 0:
		v0, v1 = '1', '0'
	}

	cookieChar := byte('n')
	if len(r.Header["Cookie"]) > 0 {
		cookieChar = 'c'
	}
	refererChar := byte('n')
	if len(r.Header["Referer"]) > 0 {
		refererChar = 'r'
	}

	var a0, a1 byte = '0', '0'
	if r.TLS != nil {
		if p := r.TLS.NegotiatedProtocol; len(p) >= 2 {
			a0, a1 = p[0], p[len(p)-1]
		} else if len(p) == 1 {
			a0, a1 = p[0], '0'
		}
	}

	mask, count := ja4hHeaderMask(r.Header)

	// 10 prefix bytes, '_', then 12 hex bytes.
	var out [23]byte
	out[0], out[1] = m0, m1
	out[2], out[3] = v0, v1
	out[4], out[5] = cookieChar, refererChar
	switch {
	case count < 10:
		out[6], out[7] = '0', byte('0'+count)
	case count < 100:
		out[6], out[7] = byte('0'+count/10), byte('0'+count%10)
	default:
		out[6], out[7] = '9', '9'
	}
	out[8], out[9] = a0, a1
	out[10] = '_'
	copy(out[11:], ja4hHeaderHash[mask])

	return string(out[:])
}
