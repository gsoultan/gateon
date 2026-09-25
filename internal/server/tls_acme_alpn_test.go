// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/tls"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/crypto/acme"

	"github.com/gsoultan/gateon/internal/config"
	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestACMERouteKeepsTheValidationProtocolUnderItsOption selects the handshake
// config for an ACME route whose TLS option sets its own ALPN list. The
// option's list replaces the base one, and without acme-tls/1 the CA's
// TLS-ALPN-01 validation for that host could never complete.
func TestACMERouteKeepsTheValidationProtocolUnderItsOption(t *testing.T) {
	resetTLSCaches(t)
	const host = "acme-alpn.example.com"
	dir := t.TempDir()
	ctx := context.Background()
	routesReg := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	tlsOptReg := config.NewTLSOptionRegistry(filepath.Join(dir, "tls_options.json"))
	globalsReg := config.NewGlobalRegistry(filepath.Join(dir, "global.json"))
	if err := tlsOptReg.Update(ctx, &gateonv1.TLSOption{Id: "opt-h2", Name: "h2 only", AlpnProtocols: []string{"h2"}}); err != nil {
		t.Fatal(err)
	}
	if err := routesReg.Update(ctx, &gateonv1.Route{
		Id: "r-acme-alpn", ServiceId: "svc", Rule: "Host(`" + host + "`)",
		Tls: &gateonv1.RouteTLSConfig{AcmeEnabled: true, OptionId: "opt-h2"},
	}); err != nil {
		t.Fatal(err)
	}
	cfg := baseTLSConfig()
	SetupSNI(cfg, gtls.NewManager(gtls.Config{}), SNIDeps{RouteStore: routesReg, GlobalStore: globalsReg, TLSOptStore: tlsOptReg})
	selected, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{ServerName: host})
	if err != nil || selected == nil {
		t.Fatalf("GetConfigForClient: cfg=%v err=%v", selected, err)
	}
	if !slices.Contains(selected.NextProtos, acme.ALPNProto) || !slices.Contains(selected.NextProtos, "h2") {
		t.Fatalf("ACME route NextProtos = %v, want the option's h2 and %s", selected.NextProtos, acme.ALPNProto)
	}
}
