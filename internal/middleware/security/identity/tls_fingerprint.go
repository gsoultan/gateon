// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"hash"
	"net"
	"slices"
	"sync"

	"github.com/gsoultan/gateon/internal/logger"
)

type tlsContextKey string

const (
	ConnContextKey tlsContextKey = "net-conn"
)

const numShards = 16

// maxFingerprintsPerShard bounds each shard's connection map.
//
// The map is keyed on the client's IP:port and written from the TLS handshake
// callback, which has no guaranteed teardown partner. RemoveFingerprints has
// exactly one non-test caller -- the http.Server ConnState hook on the
// HTTP/1.1-2 entrypoint -- so the HTTP/3 listener, which has no ConnState, and
// the bare TCP accept loop in start_servers.go both write entries that are
// never removed. A QUIC Initial packet or a TCP connect plus ClientHello is
// enough to mint one, and ephemeral source ports make every reconnect from a
// single address a fresh key.
//
// A bound rather than a third teardown hook, because the next TLS-terminating
// path added will reintroduce the leak otherwise. 16 shards x 4096 is 65,536
// live handshakes, well past what the 2-core target sustains, at roughly
// 130-250 bytes each.
const maxFingerprintsPerShard = 4096

var (
	shards [numShards]*fingerprintShard

	// Logged once: the cap is hit per handshake when it is hit at all, and an
	// operator needs to know it happened, not how often.
	shardFullOnce sync.Once

	sha256Pool = sync.Pool{
		New: func() any {
			return sha256.New()
		},
	}
)

type fingerprintShard struct {
	conns map[string]Fingerprints
	mu    sync.RWMutex
}

func init() {
	for i := 0; i < numShards; i++ {
		shards[i] = &fingerprintShard{
			conns: make(map[string]Fingerprints),
		}
	}
}

func getAddr(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	ra := conn.RemoteAddr()
	if ra == nil {
		return fmt.Sprintf("%p", conn)
	}
	return ra.String()
}

func getShard(addr string) *fingerprintShard {
	if addr == "" {
		return shards[0]
	}
	// FNV-1a hash for robust sharding
	var h uint64 = 14695981039346656037
	for i := 0; i < len(addr); i++ {
		h ^= uint64(addr[i])
		h *= 1099511628211
	}
	return shards[h%numShards]
}

type Fingerprints struct {
	JA4 string
}

func GetFingerprints(conn net.Conn) Fingerprints {
	addr := getAddr(conn)
	if addr == "" {
		return Fingerprints{}
	}
	s := getShard(addr)
	s.mu.RLock()
	f := s.conns[addr]
	s.mu.RUnlock()
	return f
}

func GetFingerprintsByAddr(addr string) Fingerprints {
	if addr == "" {
		return Fingerprints{}
	}
	s := getShard(addr)
	s.mu.RLock()
	f := s.conns[addr]
	s.mu.RUnlock()
	return f
}

func SetFingerprints(conn net.Conn, f Fingerprints) {
	addr := getAddr(conn)
	if addr == "" {
		return
	}
	s := getShard(addr)
	s.mu.Lock()
	defer s.mu.Unlock()

	// Overwriting an existing key never grows the map, so the bound only
	// applies to new ones.
	if _, exists := s.conns[addr]; !exists && len(s.conns) >= maxFingerprintsPerShard {
		// Refuse rather than evict. Evicting would let a flood of new
		// handshakes displace the fingerprints of connections that are still
		// open, which turns a memory bound into a correctness problem: a live
		// request would find no fingerprint and be treated as unidentified.
		// Refusing costs the new connection its JA3/JA4 -- it is still served,
		// just not fingerprinted -- and that degrades under exactly the
		// conditions where the map is already full of attacker handshakes.
		shardFullOnce.Do(func() {
			logger.L.LogWarn("tls fingerprint table is full; new connections will "+
				"not be fingerprinted until existing ones close. This is a bound, "+
				"not a failure -- but a sustained hit means handshakes are "+
				"arriving faster than they are being torn down.",
				"max_per_shard", maxFingerprintsPerShard, "shards", numShards)
		})
		return
	}
	s.conns[addr] = f
}

func RemoveFingerprints(conn net.Conn) {
	addr := getAddr(conn)
	if addr == "" {
		return
	}
	s := getShard(addr)
	s.mu.Lock()
	delete(s.conns, addr)
	s.mu.Unlock()
}

// CalcFingerprints computes the client's JA4 fingerprint as the specification
// defines it (FoxIO-LLC/ja4, technical_details/JA4.md): ja4_a is protocol,
// highest version, SNI, cipher and extension counts and ALPN; ja4_b hashes the
// sorted ciphers; ja4_c hashes the sorted extensions other than SNI and ALPN,
// then the signature algorithms in the order sent.
//
// GREASE values (RFC 8701) are left out of all of it. Chrome draws them at
// random for every connection, and hashed in they made one client a different
// fingerprint on nearly every connection -- so reputation, rate limits and
// blocks keyed on it never saw the same client twice.
func CalcFingerprints(hello *tls.ClientHelloInfo) Fingerprints {
	h := sha256Pool.Get().(hash.Hash)
	defer sha256Pool.Put(h)

	ciphers := withoutGREASE(hello.CipherSuites)
	extensions := withoutGREASE(hello.Extensions)

	var a [10]byte
	a[0] = 't'
	copy(a[1:3], ja4Version(hello.SupportedVersions))
	a[3] = 'i'
	if slices.Contains(extensions, extServerName) {
		a[3] = 'd'
	}
	writeTwoDigits(a[4:6], len(ciphers))
	writeTwoDigits(a[6:8], len(extensions))
	alpn := "00"
	if len(hello.SupportedProtos) > 0 {
		alpn = ja4ALPN(hello.SupportedProtos[0])
	}
	copy(a[8:10], alpn)

	slices.Sort(ciphers)
	hashed := slices.DeleteFunc(extensions, func(e uint16) bool {
		return e == extServerName || e == extALPN
	})
	slices.Sort(hashed)
	sigs := make([]uint16, 0, len(hello.SignatureSchemes))
	for _, s := range hello.SignatureSchemes {
		if !isGREASE(uint16(s)) {
			sigs = append(sigs, uint16(s))
		}
	}
	return Fingerprints{
		JA4: string(a[:]) + "_" + ja4Hash(h, ciphers, nil) + "_" + ja4Hash(h, hashed, sigs),
	}
}

// The extensions JA4 counts but leaves out of ja4_c: their values vary with
// the destination rather than the client.
const (
	extServerName uint16 = 0x0000
	extALPN       uint16 = 0x0010
)

// isGREASE reports whether v is one of RFC 8701's reserved values, 0x0a0a
// through 0xfafa.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func withoutGREASE(values []uint16) []uint16 {
	out := make([]uint16, 0, len(values))
	for _, v := range values {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// ja4Version is the two-character code of the highest version the client
// offers. The first entry is not it: Chrome lists a GREASE value first.
func ja4Version(versions []uint16) string {
	var highest uint16
	for _, v := range versions {
		if !isGREASE(v) && v > highest {
			highest = v
		}
	}
	switch highest {
	case tls.VersionTLS13:
		return "13"
	case tls.VersionTLS12:
		return "12"
	case tls.VersionTLS11:
		return "11"
	case tls.VersionTLS10:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

// ja4Hash is the first twelve hex characters of the SHA-256 of values as
// four-digit lowercase hex, comma-separated, then "_" and tail if there is a
// tail. An empty input is twelve zeros rather than the hash of "".
func ja4Hash(h hash.Hash, values, tail []uint16) string {
	if len(values) == 0 && len(tail) == 0 {
		return "000000000000"
	}
	h.Reset()
	writeHexList(h, values)
	if len(tail) > 0 {
		h.Write([]byte{'_'})
		writeHexList(h, tail)
	}
	var sum [sha256.Size]byte
	return hex.EncodeToString(h.Sum(sum[:0]))[:12]
}

func writeHexList(h hash.Hash, values []uint16) {
	const digits = "0123456789abcdef"
	var buf [5]byte
	for i, v := range values {
		buf[0] = ','
		buf[1], buf[2], buf[3], buf[4] = digits[v>>12], digits[v>>8&0xf], digits[v>>4&0xf], digits[v&0xf]
		if i == 0 {
			h.Write(buf[1:])
		} else {
			h.Write(buf[:])
		}
	}
}

// ja4ALPN renders the client's first ALPN value as JA4's two-character field.
//
// crypto/tls only requires a protocol name to be non-empty, so the value is
// whatever bytes the client chose, and it was copied into the fingerprint
// verbatim: an underscore added a field to a '_'-separated key, and 0xff made
// it invalid UTF-8, which proto3 will not marshal and Postgres will not store.
// The JA4 specification covers this: when either end of the value is not
// alphanumeric, use the first and last characters of its hex form instead.
func ja4ALPN(p string) string {
	switch {
	case p == "":
		return "00"
	case !isASCIIAlnum(p[0]) || !isASCIIAlnum(p[len(p)-1]):
		const hexDigits = "0123456789abcdef"
		return string([]byte{hexDigits[p[0]>>4], hexDigits[p[len(p)-1]&0x0f]})
	case len(p) == 1:
		return string([]byte{p[0], '0'})
	default:
		return string([]byte{p[0], p[len(p)-1]})
	}
}

func isASCIIAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func writeTwoDigits(buf []byte, n int) {
	if n > 99 {
		n = 99
	}
	if n < 0 {
		n = 0
	}
	buf[0] = byte('0' + (n / 10))
	buf[1] = byte('0' + (n % 10))
}
