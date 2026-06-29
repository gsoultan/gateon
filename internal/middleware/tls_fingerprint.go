package middleware

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
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
)

type fingerprintShard struct {
	conns map[net.Conn]Fingerprints
	addrs map[string]Fingerprints
	mu    sync.RWMutex
}

func init() {
	for i := 0; i < numShards; i++ {
		shards[i] = &fingerprintShard{
			conns: make(map[net.Conn]Fingerprints),
			addrs: make(map[string]Fingerprints),
		}
	}
}

func getShard(conn net.Conn) *fingerprintShard {
	// Extract the data pointer from the interface to avoid reflect.
	// An interface is two words: (itab/type, data). We use the data pointer for sharding.
	p := uintptr((*[2]unsafe.Pointer)(unsafe.Pointer(&conn))[1])
	return shards[p%numShards]
}

func getShardForAddr(addr string) *fingerprintShard {
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
	if conn == nil {
		return Fingerprints{}
	}
	s := getShard(conn)
	s.mu.RLock()
	f, ok := s.conns[conn]
	s.mu.RUnlock()
	if ok {
		return f
	}

	// Fallback to remote address if pointer identity is lost due to wrapping.
	// We avoid the String() allocation if possible, but RemoteAddr().String() is standard.
	addr := conn.RemoteAddr().String()
	as := getShardForAddr(addr)
	as.mu.RLock()
	defer as.mu.RUnlock()
	return as.addrs[addr]
}

func GetFingerprintsByAddr(addr string) Fingerprints {
	if addr == "" {
		return Fingerprints{}
	}
	s := getShardForAddr(addr)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.addrs[addr]
}

func SetFingerprints(conn net.Conn, f Fingerprints) {
	if conn == nil {
		return
	}
	s := getShard(conn)
	s.mu.Lock()
	s.conns[conn] = f
	s.mu.Unlock()

	if ra := conn.RemoteAddr(); ra != nil {
		addr := ra.String()
		as := getShardForAddr(addr)
		as.mu.Lock()
		as.addrs[addr] = f
		as.mu.Unlock()
	}
}

func RemoveFingerprints(conn net.Conn) {
	if conn == nil {
		return
	}
	s := getShard(conn)
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()

	if ra := conn.RemoteAddr(); ra != nil {
		addr := ra.String()
		as := getShardForAddr(addr)
		as.mu.Lock()
		delete(as.addrs, addr)
		as.mu.Unlock()
	}
}

// CalcFingerprints calculates a JA3-like fingerprint from ClientHelloInfo.
// Standard JA3: SSLVersion,Cipher,Extensions,EllipticCurve,EllipticCurvePointFormat
func CalcFingerprints(hello *tls.ClientHelloInfo) Fingerprints {
	sb := builderPool.Get().(*strings.Builder)
	sb.Reset()
	defer builderPool.Put(sb)

	// 1. SSLVersion (Go doesn't give us the record version easily, so we use the max supported)
	sslVersion := uint16(tls.VersionTLS12)
	if len(hello.SupportedVersions) > 0 {
		sslVersion = hello.SupportedVersions[0]
	}

	// 2. Ciphers
	for i, c := range hello.CipherSuites {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.FormatUint(uint64(c), 10))
	}
	cipherStr := sb.String()
	sb.Reset()

	// 3. Extensions (Not exposed by standard lib ClientHelloInfo)
	extensionStr := ""

	// 4. Curves
	for i, c := range hello.SupportedCurves {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.FormatUint(uint64(c), 10))
	}
	curveStr := sb.String()
	sb.Reset()

	// 5. Points
	for i, p := range hello.SupportedPoints {
		if i > 0 {
			sb.WriteByte('-')
		}
		sb.WriteString(strconv.FormatUint(uint64(p), 10))
	}
	pointStr := sb.String()
	sb.Reset()

	ja3Raw := fmt.Sprintf("%d,%s,%s,%s,%s", sslVersion, cipherStr, extensionStr, curveStr, pointStr)
	ja3Hash := fmt.Sprintf("%x", md5.Sum([]byte(ja3Raw)))

	// JA4 is more modern and includes Alpn, etc.
	version := "13"
	if sslVersion == tls.VersionTLS12 {
		version = "12"
	}

	sni := "i" // indicated
	if hello.ServerName == "" {
		sni = "d" // default
	}

	ja4_a := fmt.Sprintf("t%s%s%02d%02d%02d", version, sni, len(hello.CipherSuites), 0, len(hello.SupportedCurves))

	// ja4_b is hash of sorted ciphers
	sortedCiphers := make([]uint16, len(hello.CipherSuites))
	copy(sortedCiphers, hello.CipherSuites)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	ja4_b_raw := ""
	for _, c := range sortedCiphers {
		ja4_b_raw += strconv.FormatUint(uint64(c), 10)
	}
	ja4_b := fmt.Sprintf("%x", md5.Sum([]byte(ja4_b_raw)))[:12]

	return Fingerprints{
		JA3: ja3Hash,
		JA4: ja4_a + "_" + ja4_b,
	}
}
