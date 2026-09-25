// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
)

// crypto/tls requires an ALPN protocol name to be non-empty and nothing more,
// so the first value a client offers can be any bytes at all, and the
// handshake still succeeds as long as a later value is one the server speaks.
// CalcFingerprints copied the first and last of those bytes into JA4 verbatim.
// An underscore gave the fingerprint a fourth '_'-separated field, and 0xff
// made it invalid UTF-8, which proto3 refuses to marshal and a Postgres TEXT
// column refuses to store -- so one handshake left a fingerprint on that
// client's traces and threat records that no API response could serialise.
// The JA4 specification already says what to do: when either end of the value
// is not alphanumeric, use the ends of its hex form.
//
// Each case runs a real handshake, so the bytes are the ones crypto/tls
// actually hands the callback.
func TestJA4ALPNFieldIsTheSpecsNotTheClientsBytes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first string
		want  string
	}{
		{name: "invalid UTF-8", first: "\xff\xfe", want: "fe"},
		{name: "field separator", first: "_", want: "5f"},
		{name: "line break", first: "a\n", want: "6a"},
		{name: "ordinary", first: "h2", want: "h2"},
		{name: "ordinary with punctuation inside", first: "http/1.1", want: "h1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ja4 := CalcFingerprints(handshakeHello(t, []string{tc.first, "h2"})).JA4

			if _, err := proto.Marshal(&gateonv1.Trace{Ja4: ja4}); err != nil {
				t.Fatalf("a trace carrying JA4 %q cannot be serialised: %v", ja4, err)
			}
			parts := strings.Split(ja4, "_")
			if len(parts) != 3 || len(parts[0]) != 10 {
				t.Fatalf("JA4 %q does not have three '_'-separated parts", ja4)
			}
			if got := parts[0][8:]; got != tc.want {
				t.Fatalf("ALPN field = %q, want %q (JA4 %q)", got, tc.want, ja4)
			}
		})
	}
}

// handshakeHello completes a TLS handshake over an in-memory pipe, the client
// offering protos, and returns the ClientHelloInfo the server was handed.
func handshakeHello(t *testing.T, protos []string) *tls.ClientHelloInfo {
	t.Helper()
	cert, roots := selfSignedCert(t, "fp.test")

	hellos := make(chan *tls.ClientHelloInfo, 1)
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			hellos <- h
			return nil, nil
		},
	}
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	serverErr := make(chan error, 1)
	go func() { serverErr <- tls.Server(serverSide, serverCfg).Handshake() }()

	client := tls.Client(clientSide, &tls.Config{ServerName: "fp.test", RootCAs: roots, NextProtos: protos})
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if got := client.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("negotiated %q, want h2", got)
	}
	return <-hellos
}

func selfSignedCert(t *testing.T, host string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, roots
}
