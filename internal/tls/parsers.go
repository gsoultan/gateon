// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tls

import (
	"crypto/tls"
	"strings"

	"github.com/gsoultan/gateon/internal/logger"
)

func ParseTLSVersion(v string, defaultVer uint16) uint16 {
	vv := strings.ToUpper(strings.TrimSpace(v))
	// Normalize variants: "TLS1.2", "TLS_1_2", "TLS12", "TLS 1.2" → TLS12
	vv = strings.ReplaceAll(vv, "_", "")
	vv = strings.ReplaceAll(vv, ".", "")
	vv = strings.ReplaceAll(vv, " ", "")
	switch vv {
	case "TLS10":
		logger.L.LogWarn("TLS 1.0 selected by configuration; it is deprecated and "+
			"broken against modern attacks. Supported for legacy clients only.",
			"configured", v, "recommended", "TLS12")
		return tls.VersionTLS10
	case "TLS11":
		logger.L.LogWarn("TLS 1.1 selected by configuration; it is deprecated. "+
			"Supported for legacy clients only.",
			"configured", v, "recommended", "TLS12")
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
	var unknown []string
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
		// Check insecure suites. Accepting these is deliberate — a gateway
		// sometimes has to terminate for a client that cannot do better — but
		// choosing one should never be silent.
		for _, suite := range tls.InsecureCipherSuites() {
			if suite.Name == s || strings.ReplaceAll(suite.Name, "TLS_", "") == s {
				logger.L.LogWarn("insecure TLS cipher suite selected by configuration",
					"suite", suite.Name, "reason", tls.CipherSuiteName(suite.ID))
				ids = append(ids, suite.ID)
				found = true
				break
			}
		}
		if !found {
			unknown = append(unknown, s)
		}
	}
	if len(unknown) > 0 {
		logger.L.LogWarn("unrecognised TLS cipher suite names in configuration; they were ignored",
			"names", strings.Join(unknown, ", "))
	}
	if len(ids) == 0 {
		// Every name was unusable. Returning nil hands the connection Go's
		// defaults, which are sound — but an operator who meant to pin a suite
		// and typed it wrong would otherwise never find out.
		if len(suites) > 0 {
			logger.L.LogWarn("no usable TLS cipher suites in configuration; " +
				"falling back to the Go defaults")
		}
		return nil
	}
	return ids
}
