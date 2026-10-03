// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/mgmtaddr"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestAHostRouteToTheManagementPortServesNoDashboard is the review's attack
// (MGMT-N2, ADR 0052): a service targeting 127.0.0.1:<management port> behind
// a Host() route on a public entrypoint served the dashboard, sign-in and API
// to the internet, the management listener seeing the gateway's own loopback
// connection. The service is stored directly -- as a configuration file,
// GitOps or a name that resolves here only after it was saved would put it --
// so this is the dial-time half: the management listener registers itself as
// it binds, and the proxy will not connect to it.
func TestAHostRouteToTheManagementPortServesNoDashboard(t *testing.T) {
	dashboard := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<title>Gateon dashboard</title>")
	})
	mgmt := startManagement(t, 0, dashboard, nil)
	_, port, err := net.SplitHostPort(mgmt)
	if err != nil {
		t.Fatal(err)
	}
	if got := mgmtaddr.Port(); net.JoinHostPort("127.0.0.1", strconv.Itoa(got)) != mgmt {
		t.Fatalf("the management listener at %s registered port %d", mgmt, got)
	}

	for _, target := range []string{"http://127.0.0.1:" + port, "http://localhost:" + port} {
		services := config.NewServiceRegistry(filepath.Join(t.TempDir(), "services.json"))
		if err := services.Update(context.Background(), &gateonv1.Service{Id: "loop", Name: "loop",
			WeightedTargets: []*gateonv1.Target{{Url: target, Weight: 1}}}); err != nil {
			t.Fatal(err)
		}
		ph := proxy.NewProxyHandler(&gateonv1.Route{Id: "loop", ServiceId: "loop", Rule: "Host(`evil.example`)"}, services)
		publicEP := httptest.NewServer(ph)
		resp, err := publicEP.Client().Get(publicEP.URL + "/")
		if err != nil {
			t.Fatalf("request through the public entrypoint: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		publicEP.Close()
		ph.Close()
		if strings.Contains(string(body), "dashboard") || resp.StatusCode < 500 {
			t.Errorf("a Host route to %s answered %d %q through the public entrypoint; want a gateway error and no dashboard",
				target, resp.StatusCode, body)
		}
	}
}
