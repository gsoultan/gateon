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
	"strconv"
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

// CalcFingerprints calculates a JA4 fingerprint from ClientHelloInfo.
// JA4 (TLS Client Hello): [ja4_a]_[ja4_b]_[ja4_c]
func CalcFingerprints(hello *tls.ClientHelloInfo) Fingerprints {
	h := sha256Pool.Get().(hash.Hash)
	h.Reset()
	defer sha256Pool.Put(h)

	// --- 1. JA4_a ---
	// Protocol: t for TCP
	protocol := byte('t')

	// TLS Version
	sslVersion := uint16(tls.VersionTLS12)
	if len(hello.SupportedVersions) > 0 {
		sslVersion = hello.SupportedVersions[0]
	}
	version := "00"
	switch sslVersion {
	case tls.VersionTLS13:
		version = "13"
	case tls.VersionTLS12:
		version = "12"
	case tls.VersionTLS11:
		version = "11"
	case tls.VersionTLS10:
		version = "10"
	}

	// SNI
	sni := byte('0')
	if hello.ServerName != "" {
		if net.ParseIP(hello.ServerName) != nil {
			sni = 'i'
		} else {
			sni = 'd'
		}
	}

	// First ALPN
	alpn := "00"
	if len(hello.SupportedProtos) > 0 {
		alpn = ja4ALPN(hello.SupportedProtos[0])
	}

	var ja4a_buf [14]byte
	ja4a_buf[0] = protocol
	ja4a_buf[1] = version[0]
	ja4a_buf[2] = version[1]
	ja4a_buf[3] = sni
	writeTwoDigits(ja4a_buf[4:6], len(hello.CipherSuites))
	writeTwoDigits(ja4a_buf[6:8], len(hello.Extensions))
	writeTwoDigits(ja4a_buf[8:10], len(hello.SupportedProtos))
	ja4a_buf[10] = alpn[0]
	ja4a_buf[11] = alpn[1]
	ja4_a := string(ja4a_buf[:12])

	// --- 2. JA4_b (Sorted Ciphers) ---
	ciphers := make([]uint16, len(hello.CipherSuites))
	copy(ciphers, hello.CipherSuites)
	slices.Sort(ciphers)

	h.Reset()
	var buf [8]byte
	for i, c := range ciphers {
		if i > 0 {
			h.Write([]byte{','})
		}
		h.Write(strconv.AppendUint(buf[:0], uint64(c), 16)) // Hex lowercase
	}
	ja4_b := hex.EncodeToString(h.Sum(nil))[:12]

	// --- 3. JA4_c (Sorted Extensions) ---
	extensions := make([]uint16, len(hello.Extensions))
	copy(extensions, hello.Extensions)
	slices.Sort(extensions)

	h.Reset()
	for i, e := range extensions {
		if i > 0 {
			h.Write([]byte{','})
		}
		h.Write(strconv.AppendUint(buf[:0], uint64(e), 16)) // Hex lowercase
	}
	ja4_c := hex.EncodeToString(h.Sum(nil))[:12]

	return Fingerprints{
		JA4: ja4_a + "_" + ja4_b + "_" + ja4_c,
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
