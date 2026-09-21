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

// A route whose TLS option verifies client certificates, but whose client
// authority cannot be loaded, must not hand crypto/tls a nil ClientCAs.
// x509.VerifyOptions documents a nil Roots as "use the system roots", so the
// route that asked for mTLS against its own CA would instead accept any client
// certificate issued by a public CA. The only safe pool when the configured
// one is missing is an empty one: verification then fails for every client.
func TestSetupSNI_VerifyingClientAuthWithUnloadableCA_FailsClosed(t *testing.T) {
	resetTLSCaches(t)
	const certHost = "mtls.example.com"
	certPath, keyPath := createTempCertKey(t, certHost)

	dir := t.TempDir()
	routesReg := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	tlsOptReg := config.NewTLSOptionRegistry(filepath.Join(dir, "tls_options.json"))
	globalsReg := config.NewGlobalRegistry(filepath.Join(dir, "global.json"))

	gc := &gateonv1.GlobalConfig{Tls: &gateonv1.TlsConfig{
		Certificates: []*gateonv1.Certificate{{Id: "cert-unloadable-ca", CertFile: certPath, KeyFile: keyPath}},
		// The authority is configured, but its bundle is not on disk.
		ClientAuthorities: []*gateonv1.ClientAuthority{{
			Id: "ca-unloadable", Name: "missing", CaFile: filepath.Join(dir, "does-not-exist.pem"),
		}},
	}}
	if err := globalsReg.Update(context.Background(), gc); err != nil {
		t.Fatalf("update globals: %v", err)
	}

	cases := []struct {
		mode string
		host string
	}{
		{"RequireAndVerifyClientCert", "require.mtls.example.com"},
		{"VerifyClientCertIfGiven", "ifgiven.mtls.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			optID := "opt-unloadable-" + tc.mode
			routeID := "r-unloadable-" + tc.mode
			if err := tlsOptReg.Update(context.Background(), &gateonv1.TLSOption{
				Id: optID, Name: tc.mode, ClientAuthType: tc.mode, ClientAuthorityIds: []string{"ca-unloadable"},
			}); err != nil {
				t.Fatalf("update tls option: %v", err)
			}
			if err := routesReg.Update(context.Background(), &gateonv1.Route{
				Id: routeID, Name: routeID, ServiceId: "svc", Rule: "Host(`" + tc.host + "`)",
				Tls: &gateonv1.RouteTLSConfig{CertificateIds: []string{"cert-unloadable-ca"}, OptionId: optID},
			}); err != nil {
				t.Fatalf("update route: %v", err)
			}

			cfg := baseTLSConfig()
			SetupSNI(cfg, gtls.NewManager(gtls.Config{}), SNIDeps{
				RouteStore: routesReg, GlobalStore: globalsReg, TLSOptStore: tlsOptReg,
			})
			selected, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{ServerName: tc.host})
			if err != nil || selected == nil {
				t.Fatalf("GetConfigForClient: cfg=%v err=%v", selected, err)
			}
			if want := gtls.ParseClientAuthType(tc.mode); selected.ClientAuth != want {
				t.Fatalf("route option not applied: ClientAuth=%v, want %v", selected.ClientAuth, want)
			}
			if selected.ClientCAs == nil {
				t.Fatalf("ClientAuth=%v with ClientCAs=nil: crypto/tls verifies client certificates "+
					"against the system roots when ClientCAs is nil, so a certificate from any public CA "+
					"would satisfy this route's mTLS requirement", selected.ClientAuth)
			}
		})
	}
}
