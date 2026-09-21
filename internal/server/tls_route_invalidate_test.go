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

// The per-route tls.Config is cached by route id for the life of the process.
// Editing a route reaches the server through Invalidator.InvalidateRoute, which
// reset only the proxy cache — so a route reconfigured to require client
// certificates kept serving handshakes from the config it was first seen with.
// mTLS switched on in the dashboard was not enforced on the wire until an
// unrelated TLS change or a restart.
func TestInvalidateRoute_DropsCachedRouteTLSConfig(t *testing.T) {
	resetTLSCaches(t)
	const host = "reload.mtls.example.com"
	certPath, keyPath := createTempCertKey(t, host)
	caPath := createTempCA(t)
	ctx := context.Background()

	dir := t.TempDir()
	routesReg := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	tlsOptReg := config.NewTLSOptionRegistry(filepath.Join(dir, "tls_options.json"))
	globalsReg := config.NewGlobalRegistry(filepath.Join(dir, "global.json"))

	if err := globalsReg.Update(ctx, &gateonv1.GlobalConfig{Tls: &gateonv1.TlsConfig{
		Certificates:      []*gateonv1.Certificate{{Id: "cert-reload", CertFile: certPath, KeyFile: keyPath}},
		ClientAuthorities: []*gateonv1.ClientAuthority{{Id: "ca-reload", Name: "CA", CaFile: caPath}},
	}}); err != nil {
		t.Fatalf("update globals: %v", err)
	}
	if err := tlsOptReg.Update(ctx, &gateonv1.TLSOption{
		Id: "opt-reload", Name: "mtls", ClientAuthType: "RequireAndVerifyClientCert",
		ClientAuthorityIds: []string{"ca-reload"},
	}); err != nil {
		t.Fatalf("update tls option: %v", err)
	}
	if err := routesReg.Update(ctx, &gateonv1.Route{
		Id: "r-reload", Name: "r-reload", ServiceId: "svc", Rule: "Host(`" + host + "`)",
		Tls: &gateonv1.RouteTLSConfig{CertificateIds: []string{"cert-reload"}},
	}); err != nil {
		t.Fatalf("update route: %v", err)
	}

	cfg := baseTLSConfig()
	SetupSNI(cfg, gtls.NewManager(gtls.Config{}), SNIDeps{
		RouteStore: routesReg, GlobalStore: globalsReg, TLSOptStore: tlsOptReg,
	})
	hello := &tls.ClientHelloInfo{ServerName: host}
	before, err := cfg.GetConfigForClient(hello)
	if err != nil || before == nil {
		t.Fatalf("GetConfigForClient before the edit: cfg=%v err=%v", before, err)
	}
	if before.ClientAuth != tls.NoClientCert {
		t.Fatalf("precondition: a route without an option must not request client certs, got %v", before.ClientAuth)
	}

	// The operator attaches the mTLS option. The route service reports the edit
	// through the same invalidator call domain/route makes.
	if err := routesReg.Update(ctx, &gateonv1.Route{
		Id: "r-reload", Name: "r-reload", ServiceId: "svc", Rule: "Host(`" + host + "`)",
		Tls: &gateonv1.RouteTLSConfig{CertificateIds: []string{"cert-reload"}, OptionId: "opt-reload"},
	}); err != nil {
		t.Fatalf("update route: %v", err)
	}
	NewServerProxyInvalidator(&Server{}, nil, routesReg).InvalidateRoute("r-reload")

	after, err := cfg.GetConfigForClient(hello)
	if err != nil || after == nil {
		t.Fatalf("GetConfigForClient after the edit: cfg=%v err=%v", after, err)
	}
	if after.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("route now requires client certificates, but the handshake still uses the cached config: ClientAuth=%v", after.ClientAuth)
	}
}
