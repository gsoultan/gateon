package tls

import (
	"crypto/tls"
	"strings"
)

func ParseTLSVersion(v string, defaultVer uint16) uint16 {
	vv := strings.ToUpper(strings.TrimSpace(v))
	// Normalize variants: "TLS1.2", "TLS_1_2", "TLS12", "TLS 1.2" → TLS12
	vv = strings.ReplaceAll(vv, "_", "")
	vv = strings.ReplaceAll(vv, ".", "")
	vv = strings.ReplaceAll(vv, " ", "")
	switch vv {
	case "TLS10":
		return tls.VersionTLS10
	case "TLS11":
		return tls.VersionTLS11
	case "TLS12":
		return tls.VersionTLS12
	case "TLS13":
		return tls.VersionTLS13
	default:
		return defaultVer
	}
}

func ParseClientAuthType(v string) tls.ClientAuthType {
	switch strings.TrimSpace(v) {
	case "NoClientCert":
		return tls.NoClientCert
	case "RequestClientCert":
		return tls.RequestClientCert
	case "RequireAnyClientCert":
		return tls.RequireAnyClientCert
	case "VerifyClientCertIfGiven":
		return tls.VerifyClientCertIfGiven
	case "RequireAndVerifyClientCert":
		return tls.RequireAndVerifyClientCert
	default:
		return tls.NoClientCert
	}
}

func ParseCipherSuites(suites []string) []uint16 {
	if len(suites) == 0 {
		return nil
	}
	var ids []uint16
	for _, s := range suites {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		found := false
		// Check secure suites
		for _, suite := range tls.CipherSuites() {
			if suite.Name == s || strings.ReplaceAll(suite.Name, "TLS_", "") == s {
				ids = append(ids, suite.ID)
				found = true
				break
			}
		}
		if found {
			continue
		}
		// Check insecure suites
		for _, suite := range tls.InsecureCipherSuites() {
			if suite.Name == s || strings.ReplaceAll(suite.Name, "TLS_", "") == s {
				ids = append(ids, suite.ID)
				found = true
				break
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return ids
}
