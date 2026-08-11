// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
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
	ja4plusCtxKey     telemetryContextKey = "ja4plus"
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
func GenerateJA4H(r *http.Request) string {
	method := "o0"
	if len(r.Method) >= 2 {
		method = strings.ToLower(r.Method[:2])
	} else if len(r.Method) == 1 {
		method = strings.ToLower(r.Method) + "0"
	}

	version := "11"
	if r.ProtoMajor == 2 {
		version = "20"
	} else if r.ProtoMajor == 3 {
		version = "30"
	} else if r.ProtoMajor == 1 && r.ProtoMinor == 0 {
		version = "10"
	}

	cookieChar := byte('n')
	if r.Header.Get("Cookie") != "" {
		cookieChar = 'c'
	}

	refererChar := byte('n')
	if r.Header.Get("Referer") != "" {
		refererChar = 'r'
	}

	alpn := "00"
	if r.TLS != nil && len(r.TLS.NegotiatedProtocol) > 0 {
		p := r.TLS.NegotiatedProtocol
		if len(p) >= 2 {
			alpn = string([]byte{p[0], p[len(p)-1]})
		} else if len(p) == 1 {
			alpn = string([]byte{p[0], '0'})
		}
	}

	// Optimized header stable hashing
	h := hashPool.Get().(hash.Hash)
	h.Reset()

	var localKeys [64]string
	keys := localKeys[:0]
	headerCount := 0

	for k := range r.Header {
		// Ultra-Stable Fingerprint Strategy:
		// We only include headers that are the most stable and representative
		// of a unique browser/client identity to avoid identity drift
		// in complex middleware chains.
		kl := strings.ToLower(k)
		if kl == "user-agent" || kl == "accept-language" {
			keys = append(keys, k)
			headerCount++
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		_, _ = h.Write([]byte(k))
		_, _ = h.Write([]byte{','})
	}
	headerHashBytes := h.Sum(nil)
	headerHash := hex.EncodeToString(headerHashBytes)[:12]
	hashPool.Put(h)

	var ja4ha [10]byte
	ja4ha[0] = method[0]
	ja4ha[1] = method[1]
	ja4ha[2] = version[0]
	ja4ha[3] = version[1]
	ja4ha[4] = cookieChar
	ja4ha[5] = refererChar
	if headerCount < 10 {
		ja4ha[6] = '0'
		ja4ha[7] = byte('0' + headerCount)
	} else if headerCount < 100 {
		ja4ha[6] = byte('0' + headerCount/10)
		ja4ha[7] = byte('0' + headerCount%10)
	} else {
		ja4ha[6] = '9'
		ja4ha[7] = '9'
	}
	ja4ha[8] = alpn[0]
	ja4ha[9] = alpn[1]

	return string(ja4ha[:]) + "_" + headerHash
}
