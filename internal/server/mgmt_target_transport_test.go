// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/mgmtaddr"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// loopMgmtPort stands in for the management listener's port.
const loopMgmtPort = "18736"

// managementTargetForms are ways an operator can write the management
// listener's address as a service target (review finding MGMT-N2).
var managementTargetForms = []string{
	"http://127.0.0.1:" + loopMgmtPort, "http://127.0.0.2:" + loopMgmtPort, "http://[::1]:" + loopMgmtPort,
	"http://0.0.0.0:" + loopMgmtPort, "http://[::]:" + loopMgmtPort, "http://[::ffff:127.0.0.1]:" + loopMgmtPort,
	"http://localhost:" + loopMgmtPort, "h2c://localhost:" + loopMgmtPort, "tcp://127.0.0.1:" + loopMgmtPort,
	"127.0.0.1:" + loopMgmtPort,
}

func loopService(id, target string) *gateonv1.Service {
	return &gateonv1.Service{Id: id, Name: id, BackendType: "http",
		WeightedTargets: []*gateonv1.Target{{Url: target, Weight: 1}}}
}

func (a *routeAPI) hasService(id string) bool {
	_, ok := a.services.Get(context.Background(), id)
	return ok
}

// putServiceRESTBody is putServiceREST with the answer's body.
func (a *routeAPI) putServiceRESTBody(t *testing.T, svc *gateonv1.Service) (int, string) {
	t.Helper()
	body, err := protojson.Marshal(svc)
	if err != nil {
		t.Fatal(err)
	}
	return a.send(t, http.MethodPut, "/v1/services", string(body))
}

// importServices posts services to the config import and returns the errors
// it reports.
func (a *routeAPI) importServices(t *testing.T, svcs ...*gateonv1.Service) []string {
	t.Helper()
	// The import reads encoding/json's spelling (weighted_targets), which is
	// what the export writes.
	body, err := json.Marshal(map[string]any{"services": svcs})
	if err != nil {
		t.Fatal(err)
	}
	code, out := a.send(t, http.MethodPost, "/v1/config/import", string(body))
	if code != http.StatusOK {
		t.Fatalf("POST /v1/config/import: %d %s", code, out)
	}
	var res struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("import answer: %v in %s", err, out)
	}
	return res.Errors
}

// TestAServiceOnTheManagementListenerIsRefusedOnEveryTransport (ADR 0052): a
// target on the management port at a local address is refused by REST, gRPC
// and config import alike, naming the target, and nothing is stored. Each of
// them saved it before, and a Host() route to it served the dashboard
// publicly from loopback.
func TestAServiceOnTheManagementListenerIsRefusedOnEveryTransport(t *testing.T) {
	prev := mgmtaddr.Register(18736)
	t.Cleanup(func() { mgmtaddr.Register(prev) })
	a := newRouteAPI(t, auth.RoleAdmin)
	for _, target := range managementTargetForms {
		t.Run("REST/"+target, func(t *testing.T) {
			code, body := a.putServiceRESTBody(t, loopService("rest-loop", target))
			if code != http.StatusBadRequest || !strings.Contains(body, target) {
				t.Fatalf("PUT /v1/services with %s: %d %q, want 400 naming the target", target, code, body)
			}
			if a.hasService("rest-loop") {
				t.Fatalf("a service targeting %s was stored over REST", target)
			}
		})
		t.Run("gRPC/"+target, func(t *testing.T) {
			_, err := a.grpc.UpdateService(context.Background(),
				&gateonv1.UpdateServiceRequest{Service: loopService("grpc-loop", target)})
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), target) {
				t.Fatalf("gRPC UpdateService with %s: %v, want InvalidArgument naming the target", target, err)
			}
			if a.hasService("grpc-loop") {
				t.Fatalf("a service targeting %s was stored over gRPC", target)
			}
		})
		t.Run("import/"+target, func(t *testing.T) {
			good := loopService("import-good", "http://192.0.2.10:"+loopMgmtPort)
			errs := a.importServices(t, good, loopService("import-loop", target))
			if len(errs) != 1 || !strings.Contains(errs[0], "import-loop") || !strings.Contains(errs[0], target) {
				t.Fatalf("import with %s: errors %v, want one naming import-loop and the target", target, errs)
			}
			if a.hasService("import-loop") || !a.hasService("import-good") {
				t.Fatalf("import with %s: loop stored %v, good stored %v; want only the good one",
					target, a.hasService("import-loop"), a.hasService("import-good"))
			}
		})
	}
}
