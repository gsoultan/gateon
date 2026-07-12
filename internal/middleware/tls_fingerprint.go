package middleware

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"hash"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unsafe"
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
	conns map[net.Conn]Fingerprints
	mu    sync.RWMutex
}

func init() {
	for i := 0; i < numShards; i++ {
		shards[i] = &fingerprintShard{
			conns: make(map[net.Conn]Fingerprints),
		}
	}
}

func getShard(conn net.Conn) *fingerprintShard {
	// Extract the data pointer from the interface to avoid reflect.
	// An interface is two words: (itab/type, data). We use the data pointer for sharding.
	p := uintptr((*[2]unsafe.Pointer)(unsafe.Pointer(&conn))[1])
	return shards[p%numShards]
}

type Fingerprints struct {
	JA3 string
	JA4 string
}

func GetFingerprints(conn net.Conn) Fingerprints {
	if conn == nil {
		return Fingerprints{}
	}
	s := getShard(conn)
	s.mu.RLock()
	f := s.conns[conn]
	s.mu.RUnlock()
	return f
}

func GetFingerprintsByAddr(addr string) Fingerprints {
	// This was only for the IP fallback which we've removed for performance and correctness
	// behind proxies like Cloudflare.
	return Fingerprints{}
}

func SetFingerprints(conn net.Conn, f Fingerprints) {
	if conn == nil {
		return
	}
	s := getShard(conn)
	s.mu.Lock()
	s.conns[conn] = f
	s.mu.Unlock()
}

func RemoveFingerprints(conn net.Conn) {
	if conn == nil {
		return
	}
	s := getShard(conn)
	s.mu.Lock()
	delete(s.conns, conn)
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

	ja3Hash := hex.EncodeToString(h.Sum(nil))

	// JA4 Calculation
	version := "13"
	if sslVersion == tls.VersionTLS12 {
		version = "12"
	}
	sni := "i"
	if hello.ServerName == "" {
		sni = "d"
	}

	ja4_a := fmt.Sprintf("t%s%s%02d%02d%02d", version, sni, len(hello.CipherSuites), 0, len(hello.SupportedCurves))

	h.Reset()
	// ja4_b is hash of sorted ciphers
	// We use a small local slice for sorting to avoid excessive allocations
	var localCiphers [64]uint16
	var ciphers []uint16
	if len(hello.CipherSuites) <= 64 {
		ciphers = localCiphers[:len(hello.CipherSuites)]
		copy(ciphers, hello.CipherSuites)
	} else {
		ciphers = make([]uint16, len(hello.CipherSuites))
		copy(ciphers, hello.CipherSuites)
	}

	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	for _, c := range ciphers {
		h.Write(strconv.AppendUint(buf[:0], uint64(c), 10))
	}
	ja4_b := hex.EncodeToString(h.Sum(nil))[:12]

	return Fingerprints{
		JA3: ja3Hash,
		JA4: ja4_a + "_" + ja4_b,
	}
}
