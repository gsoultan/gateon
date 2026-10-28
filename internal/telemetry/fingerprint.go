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
	"sync"
	"sync/atomic"

	"github.com/gsoultan/gateon/internal/request"
)

type telemetryContextKey string

const (
	fingerprintCtxKey telemetryContextKey = "fingerprint"
	ja4hCtxKey        telemetryContextKey = "ja4h"
	ja4plusCtxKey     telemetryContextKey = "ja4plus"
)

var (
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

// GenerateJA4H builds the JA4H fingerprint: the interned JA4H+ without its
// leading "_" (see GenerateJA4HPlus), so it allocates only for a request the
// table cannot hold.
//
// The layout is load-bearing beyond this package: repid cuts the reputation
// class out of it by position, leaving out the method, cookie and referer bytes
// a client varies per request (ADR 0024). It cannot import this package, so
// TestReputationIdentityFollowsTheJA4HLayout is what fails if the two drift.
func GenerateJA4H(r *http.Request) string {
	return GenerateJA4HPlus(r)[1:]
}

// ja4hLen is the length of a JA4H: 10 prefix bytes, '_', then 12 hex bytes.
const ja4hLen = 23

// GenerateJA4HPlus is the JA4+ of a request with no JA4 -- "_" and its JA4H
// -- in one string, so the entrypoint, which keeps both, has one string for
// both. The JA4H is the result from its second byte.
//
// A JA4H is a function of eight bytes and a two-bit mask, and for the methods
// and protocols real traffic uses the whole value space is 2,304 strings, so
// each is built once, the first time a request produces it, and every later
// request gets that string back (ja4hPlusTable). Anything outside the table --
// an unlisted method, an unusual ALPN -- is built per request, as every request
// was before, so a client choosing its method cannot grow the table.
func GenerateJA4HPlus(r *http.Request) string {
	p := ja4hPartsOf(r)
	slot := p.tableSlot()
	if slot >= 0 {
		if s := ja4hPlusTable[slot].Load(); s != nil {
			return *s
		}
	}
	var out [ja4hLen + 1]byte
	out[0] = '_'
	p.write(out[1:])
	s := string(out[:])
	if slot >= 0 {
		// Two requests filling the same slot store equal strings; either
		// one is right.
		ja4hPlusTable[slot].Store(&s)
	}
	return s
}

// ja4hParts is everything a JA4H is built from.
type ja4hParts struct {
	m0, m1 byte // method, first two bytes, lower case
	v0, v1 byte // HTTP version
	cookie byte // 'c' or 'n'
	refer  byte // 'r' or 'n'
	a0, a1 byte // ALPN, first and last byte
	mask   int  // ja4hHeaderMask
	count  int
}

func ja4hPartsOf(r *http.Request) ja4hParts {
	p := ja4hParts{v0: '1', v1: '1', cookie: 'n', refer: 'n', a0: '0', a1: '0'}
	p.m0, p.m1 = lowerASCII2(r.Method)
	switch {
	case r.ProtoMajor == 2:
		p.v0, p.v1 = '2', '0'
	case r.ProtoMajor == 3:
		p.v0, p.v1 = '3', '0'
	case r.ProtoMajor == 1 && r.ProtoMinor == 0:
		p.v0, p.v1 = '1', '0'
	}
	if len(r.Header["Cookie"]) > 0 {
		p.cookie = 'c'
	}
	if len(r.Header["Referer"]) > 0 {
		p.refer = 'r'
	}
	if r.TLS != nil {
		if a := r.TLS.NegotiatedProtocol; len(a) >= 2 {
			p.a0, p.a1 = a[0], a[len(a)-1]
		} else if len(a) == 1 {
			p.a0, p.a1 = a[0], '0'
		}
	}
	p.mask, p.count = ja4hHeaderMask(r.Header)
	return p
}

// write puts the JA4H into out, which holds ja4hLen bytes.
func (p ja4hParts) write(out []byte) {
	out[0], out[1] = p.m0, p.m1
	out[2], out[3] = p.v0, p.v1
	out[4], out[5] = p.cookie, p.refer
	switch {
	case p.count < 10:
		out[6], out[7] = '0', byte('0'+p.count)
	case p.count < 100:
		out[6], out[7] = byte('0'+p.count/10), byte('0'+p.count%10)
	default:
		out[6], out[7] = '9', '9'
	}
	out[8], out[9] = p.a0, p.a1
	out[10] = '_'
	copy(out[11:], ja4hHeaderHash[p.mask])
}

// ja4hMethods and ja4hALPNs are the method and ALPN byte pairs the table
// holds: the methods of RFC 9110 and PATCH, and no ALPN (plaintext, or TLS
// without one), h2, http/1.1 and h3.
var (
	ja4hMethods = [...][2]byte{{'g', 'e'}, {'p', 'o'}, {'p', 'u'}, {'d', 'e'}, {'p', 'a'}, {'h', 'e'}, {'o', 'p'}, {'c', 'o'}, {'t', 'r'}}
	ja4hALPNs   = [...][2]byte{{'0', '0'}, {'h', '2'}, {'h', '1'}, {'h', '3'}}
	ja4hVersion = [...][2]byte{{'1', '1'}, {'2', '0'}, {'3', '0'}, {'1', '0'}}
)

const ja4hTableSize = len(ja4hMethods) * len(ja4hVersion) * 2 * 2 * len(ja4hHeaderHash) * len(ja4hALPNs)

// ja4hPlusTable holds each JA4H+ the table's methods and protocols can
// produce, once seen. Its size is fixed -- 2,304 pointers, and at most that
// many 24-byte strings -- whatever the traffic.
var ja4hPlusTable [ja4hTableSize]atomic.Pointer[string]

// tableSlot is p's index in ja4hPlusTable, or -1 if the table does not hold
// it. Every byte write emits is part of the index, so two requests share a
// slot only when they share a JA4H; the count is not, because the mask
// determines it.
func (p ja4hParts) tableSlot() int {
	m := pairIndex(ja4hMethods[:], p.m0, p.m1)
	v := pairIndex(ja4hVersion[:], p.v0, p.v1)
	a := pairIndex(ja4hALPNs[:], p.a0, p.a1)
	if m < 0 || v < 0 || a < 0 {
		return -1
	}
	slot := m
	slot = slot*len(ja4hVersion) + v
	slot = slot*2 + boolIndex(p.cookie == 'c')
	slot = slot*2 + boolIndex(p.refer == 'r')
	slot = slot*len(ja4hHeaderHash) + p.mask
	return slot*len(ja4hALPNs) + a
}

func pairIndex(pairs [][2]byte, b0, b1 byte) int {
	for i, p := range pairs {
		if p[0] == b0 && p[1] == b1 {
			return i
		}
	}
	return -1
}

func boolIndex(b bool) int {
	if b {
		return 1
	}
	return 0
}
