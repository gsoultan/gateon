// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// A route's TLS option has to apply whichever way the route gets its
// certificate. The ACME branch of buildTLSConfigForRoute returned as soon as it
// had wired GetCertificate, before the option was looked at, so an ACME route
// configured to require client certificates negotiated with ClientAuth at its
// zero value -- NoClientCert -- and served every client. The dashboard showed
// the option attached; the handshake never asked for a certificate. The same
// early return dropped the option's minimum version and cipher suites.
func TestSetupSNI_AcmeRouteAppliesItsTLSOption(t *testing.T) {
	resetTLSCaches(t)
	const host = "acme-mtls.example.com"
	caPath := createTempCA(t)

	dir := t.TempDir()
	routesReg := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	tlsOptReg := config.NewTLSOptionRegistry(filepath.Join(dir, "tls_options.json"))
	globalsReg := config.NewGlobalRegistry(filepath.Join(dir, "global.json"))
	ctx := context.Background()

	if err := globalsReg.Update(ctx, &gateonv1.GlobalConfig{Tls: &gateonv1.TlsConfig{
		ClientAuthorities: []*gateonv1.ClientAuthority{{Id: "ca1", Name: "CA", CaFile: caPath}},
	}}); err != nil {
		t.Fatalf("update globals: %v", err)
	}
	if err := tlsOptReg.Update(ctx, &gateonv1.TLSOption{
		Id: "opt-acme-mtls", Name: "acme mtls", ClientAuthType: "RequireAndVerifyClientCert",
		ClientAuthorityIds: []string{"ca1"}, MinTlsVersion: "TLS1.3",
	}); err != nil {
		t.Fatalf("update tls option: %v", err)
	}
	if err := routesReg.Update(ctx, &gateonv1.Route{
		Id: "r-acme", ServiceId: "svc", Rule: "Host(`" + host + "`)",
		Tls: &gateonv1.RouteTLSConfig{AcmeEnabled: true, OptionId: "opt-acme-mtls"},
	}); err != nil {
		t.Fatalf("update route: %v", err)
	}

	cfg := baseTLSConfig()
	SetupSNI(cfg, gtls.NewManager(gtls.Config{}), SNIDeps{
		RouteStore: routesReg, GlobalStore: globalsReg, TLSOptStore: tlsOptReg,
	})
	selected, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{ServerName: host})
	if err != nil || selected == nil {
		t.Fatalf("GetConfigForClient: cfg=%v err=%v", selected, err)
	}
	// The ACME wiring itself must survive: the certificate still comes from
	// the manager.
	if selected.GetCertificate == nil {
		t.Fatal("ACME route lost its GetCertificate hook")
	}
	if selected.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ACME route ClientAuth = %v, want RequireAndVerifyClientCert: the route's TLS option "+
			"was never applied, so the handshake asks no client for a certificate", selected.ClientAuth)
	}
	if selected.ClientCAs == nil {
		t.Error("ACME route ClientCAs = nil: the option's client authority was not bound")
	}
	if selected.MinVersion != tls.VersionTLS13 {
		t.Errorf("ACME route MinVersion = %#x, want TLS 1.3 from the route's option", selected.MinVersion)
	}
}
