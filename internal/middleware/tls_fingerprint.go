// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"hash"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
)

type tlsContextKey string

const (
	ConnContextKey tlsContextKey = "net-conn"
	numShards                    = 16
)

var (
	shards [numShards]*fingerprintShard

	builderPool = sync.Pool{
		New: func() any {
			return &strings.Builder{}
		},
	}

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
	s.conns[addr] = f
	s.mu.Unlock()
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
		p := hello.SupportedProtos[0]
		if len(p) >= 2 {
			alpn = string([]byte{p[0], p[len(p)-1]})
		} else if len(p) == 1 {
			alpn = string([]byte{p[0], '0'})
		}
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
