// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/testutil"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// A BY_HEADER service presents the client certificate whose match header the
// request carries -- and the request's headers are the client's. Sending
// "X-Tenant: admin" was enough to make the gateway authenticate to the backend
// as the admin identity, on a route with nothing on it that ever set the
// header. The header is the gateway's to set: a client's copy is removed when
// the route is entered, so only the route's own middlewares can choose.
func TestClientCannotChooseTheBackendClientIdentity(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer := "none"
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			peer = r.TLS.PeerCertificates[0].DNSNames[0]
		}
		_, _ = io.WriteString(w, peer+" tenant="+r.Header.Get("X-Tenant"))
	}))
	backend.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	backend.StartTLS()
	defer backend.Close()

	services := identityService(t, backend.URL)
	mwStore := fakeMWStore{m: map[string]*gateonv1.Middleware{
		"as-admin": {Id: "as-admin", Type: "headers", Config: map[string]string{"set_request_X-Tenant": "admin"}},
	}}
	plain := identityGateway(t, services, mwStore, &gateonv1.Route{Id: "plain", ServiceId: "svc"})
	asAdmin := identityGateway(t, services, mwStore,
		&gateonv1.Route{Id: "as-admin", ServiceId: "svc", Middlewares: []string{"as-admin"}})

	// Control: when the route itself sets the header the identity is
	// presented, so the refusal below is the guard and not a broken identity.
	if got := getWithTenant(t, asAdmin, ""); got != "admin.identity.test tenant=admin" {
		t.Fatalf("control: a route that sets X-Tenant itself got %q from the backend; the "+
			"identity it selects was not presented, so this test would prove nothing", got)
	}

	if got := getWithTenant(t, plain, "admin"); got != "none tenant=" {
		t.Fatalf("a client that sent X-Tenant: admin on a route that never sets it got %q from the "+
			"backend; the gateway presented the identity the client named", got)
	}
}

func identityService(t *testing.T, backendURL string) *config.ServiceRegistry {
	t.Helper()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "admin.crt")
	keyFile := filepath.Join(dir, "admin.key")
	cert, err := testutil.GenerateCert([]string{"admin.identity.test"})
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	if err := testutil.SaveCertToPEM(cert, certFile, keyFile); err != nil {
		t.Fatalf("save certificate: %v", err)
	}
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	if err := services.Update(context.Background(), &gateonv1.Service{
		Id:              "svc",
		WeightedTargets: []*gateonv1.Target{{Url: backendURL, Weight: 1}},
		TlsClientConfig: &gateonv1.TlsClientConfig{
			Enabled:               true,
			SkipVerify:            true,
			CertSelectionStrategy: gateonv1.TlsClientCertSelectionStrategy_TLS_CLIENT_CERT_SELECTION_STRATEGY_BY_HEADER,
			CertIdentities: []*gateonv1.TlsClientIdentity{{
				Id: "admin", CertFile: certFile, KeyFile: keyFile,
				MatchHeader: "X-Tenant", MatchHeaderValue: "admin",
			}},
		},
	}); err != nil {
		t.Fatalf("update service: %v", err)
	}
	return services
}

func identityGateway(t *testing.T, services *config.ServiceRegistry, mwStore fakeMWStore, rt *gateonv1.Route) string {
	t.Helper()
	rt.Rule, rt.Type = "PathPrefix(`/`)", "http"
	ph := proxy.NewProxyHandler(rt, services)
	t.Cleanup(ph.Close)
	chain := ApplyRouteMiddlewares(ph, rt, nil, mwStore, fakeGlobalStore{cfg: &gateonv1.GlobalConfig{}}, nil, nil)
	srv := httptest.NewServer(middleware.EntryPoint("web", "web", false)(chain))
	t.Cleanup(srv.Close)
	return srv.URL
}

func getWithTenant(t *testing.T, gatewayURL, tenant string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, gatewayURL+"/", nil)
	if tenant != "" {
		req.Header.Set("X-Tenant", tenant)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}
