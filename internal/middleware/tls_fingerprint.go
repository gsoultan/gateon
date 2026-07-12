package middleware

import (
	"crypto/md5"
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

	md5Pool = sync.Pool{
		New: func() any {
			return md5.New()
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
	JA3 string
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

// CalcFingerprints calculates a JA3-like fingerprint from ClientHelloInfo.
// Standard JA3: SSLVersion,Cipher,Extensions,EllipticCurve,EllipticCurvePointFormat
func CalcFingerprints(hello *tls.ClientHelloInfo) Fingerprints {
	h := md5Pool.Get().(hash.Hash)
	h.Reset()
	defer md5Pool.Put(h)

	// 1. SSLVersion
	sslVersion := uint16(tls.VersionTLS12)
	if len(hello.SupportedVersions) > 0 {
		sslVersion = hello.SupportedVersions[0]
	}

	// Use a small buffer to avoid fmt.Fprintf
	var buf [16]byte

	// JA3 Calculation
	// 1. Version
	h.Write(strconv.AppendUint(buf[:0], uint64(sslVersion), 10))
	h.Write([]byte{','})

	// 2. Ciphers
	for i, c := range hello.CipherSuites {
		if i > 0 {
			h.Write([]byte{'-'})
		}
		h.Write(strconv.AppendUint(buf[:0], uint64(c), 10))
	}
	h.Write([]byte{','})

	// 3. Extensions (Not exposed)
	h.Write([]byte{','})

	// 4. Curves
	for i, c := range hello.SupportedCurves {
		if i > 0 {
			h.Write([]byte{'-'})
		}
		h.Write(strconv.AppendUint(buf[:0], uint64(c), 10))
	}
	h.Write([]byte{','})

	// 5. Points
	for i, p := range hello.SupportedPoints {
		if i > 0 {
			h.Write([]byte{'-'})
		}
		h.Write(strconv.AppendUint(buf[:0], uint64(p), 10))
	}

	ja3Sum := h.Sum(nil)

	// JA4 Calculation
	version := "13"
	if sslVersion == tls.VersionTLS12 {
		version = "12"
	}
	sni := "i"
	if hello.ServerName == "" {
		sni = "d"
	}

	// Optimized ja4_a calculation to avoid fmt.Sprintf
	var ja4a_buf [12]byte
	ja4a_buf[0] = 't'
	ja4a_buf[1] = version[0]
	ja4a_buf[2] = version[1]
	ja4a_buf[3] = sni[0]
	writeTwoDigits(ja4a_buf[4:6], len(hello.CipherSuites))
	writeTwoDigits(ja4a_buf[6:8], 0) // extensions not exposed
	writeTwoDigits(ja4a_buf[8:10], len(hello.SupportedCurves))
	ja4_a := string(ja4a_buf[:10])

	h.Reset()
	// ja4_b is hash of sorted ciphers
	var localCiphers [64]uint16
	var ciphers []uint16
	if len(hello.CipherSuites) <= 64 {
		ciphers = localCiphers[:len(hello.CipherSuites)]
		copy(ciphers, hello.CipherSuites)
	} else {
		ciphers = make([]uint16, len(hello.CipherSuites))
		copy(ciphers, hello.CipherSuites)
	}

	slices.Sort(ciphers)
	for _, c := range ciphers {
		h.Write(strconv.AppendUint(buf[:0], uint64(c), 10))
	}
	ja4Sum := h.Sum(nil)

	return Fingerprints{
		JA3: hex.EncodeToString(ja3Sum),
		JA4: ja4_a + "_" + hex.EncodeToString(ja4Sum)[:12],
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
