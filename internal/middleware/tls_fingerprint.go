package middleware

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

type tlsContextKey string

const (
	ConnContextKey tlsContextKey = "net-conn"
)

var (
	fingerprintMap = make(map[net.Conn]Fingerprints)
	mapMu          sync.RWMutex
)

type Fingerprints struct {
	JA3 string
	JA4 string
}

func GetFingerprints(conn net.Conn) Fingerprints {
	mapMu.RLock()
	defer mapMu.RUnlock()
	return fingerprintMap[conn]
}

func SetFingerprints(conn net.Conn, f Fingerprints) {
	mapMu.Lock()
	defer mapMu.Unlock()
	fingerprintMap[conn] = f
}

func RemoveFingerprints(conn net.Conn) {
	mapMu.Lock()
	defer mapMu.Unlock()
	delete(fingerprintMap, conn)
}

// CalcFingerprints calculates a JA3-like fingerprint from ClientHelloInfo.
// Standard JA3: SSLVersion,Cipher,Extensions,EllipticCurve,EllipticCurvePointFormat
func CalcFingerprints(hello *tls.ClientHelloInfo) Fingerprints {
	// 1. SSLVersion (Go doesn't give us the record version easily, so we use the max supported)
	sslVersion := uint16(tls.VersionTLS12)
	if len(hello.SupportedVersions) > 0 {
		sslVersion = hello.SupportedVersions[0]
	}

	// 2. Ciphers
	ciphers := make([]string, len(hello.CipherSuites))
	for i, c := range hello.CipherSuites {
		ciphers[i] = fmt.Sprintf("%d", c)
	}
	cipherStr := strings.Join(ciphers, "-")

	// 3. Extensions (Not exposed by standard lib ClientHelloInfo)
	// We'll skip this for a basic implementation or use a placeholder.
	extensionStr := ""

	// 4. Curves
	curves := make([]string, len(hello.SupportedCurves))
	for i, c := range hello.SupportedCurves {
		curves[i] = fmt.Sprintf("%d", c)
	}
	curveStr := strings.Join(curves, "-")

	// 5. Points
	points := make([]string, len(hello.SupportedPoints))
	for i, p := range hello.SupportedPoints {
		points[i] = fmt.Sprintf("%d", p)
	}
	pointStr := strings.Join(points, "-")

	ja3Raw := fmt.Sprintf("%d,%s,%s,%s,%s", sslVersion, cipherStr, extensionStr, curveStr, pointStr)
	ja3Hash := fmt.Sprintf("%x", md5.Sum([]byte(ja3Raw)))

	// JA4 is more modern and includes Alpn, etc.
	// This is a simplified version: t(tls) 13(version) d(direction) 1(sni) 11(ciphers) 08(extensions) alpn
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
		ja4_b_raw += fmt.Sprintf("%d", c)
	}
	ja4_b := fmt.Sprintf("%x", md5.Sum([]byte(ja4_b_raw)))[:12]

	return Fingerprints{
		JA3: ja3Hash,
		JA4: ja4_a + "_" + ja4_b,
	}
}
