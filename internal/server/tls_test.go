package server

import (
	"crypto/tls"
	"testing"
)

func TestParseTLSVersion(t *testing.T) {
	cases := []struct {
		in   string
		want uint16
	}{
		{"TLS1.2", tls.VersionTLS12},
		{"tls1.2", tls.VersionTLS12},
		{"TLS12", tls.VersionTLS12},
		{"TLS_1_2", tls.VersionTLS12},
		{"TLS1.3", tls.VersionTLS13},
		{"TLS13", tls.VersionTLS13},
		{"unknown", tls.VersionTLS12}, // default fallback
	}
	for _, c := range cases {
		if got := parseTLSVersion(c.in); got != c.want {
			t.Fatalf("parseTLSVersion(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseClientAuthType(t *testing.T) {
	cases := []struct {
		in   string
		want tls.ClientAuthType
	}{
		{"NoClientCert", tls.NoClientCert},
		{"RequestClientCert", tls.RequestClientCert},
		{"RequireAnyClientCert", tls.RequireAnyClientCert},
		{"VerifyClientCertIfGiven", tls.VerifyClientCertIfGiven},
		{"RequireAndVerifyClientCert", tls.RequireAndVerifyClientCert},
		{"", tls.NoClientCert},
	}
	for _, c := range cases {
		if got := parseClientAuthType(c.in); got != c.want {
			t.Fatalf("parseClientAuthType(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
