// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/gsoultan/gateon/proto/gateon/v1/gateonv1connect"
)

// procedureFor builds the wire path the interceptors match on.
func procedureFor(method string) string {
	return "/" + gateonv1connect.ApiServiceName + "/" + method
}

// TestAPIPermissions_CoversEveryProcedure is what keeps this fix from decaying.
// Both interceptors deny an unmapped procedure, so a new RPC is safe by
// default — but it is also broken by default, and the person who notices would
// otherwise be a user. Reflecting over the generated handler interface turns
// "someone forgot a table entry" into a failing test at the moment the proto
// changes, which is the signal that was missing when these RPCs were first
// moved off REST.
func TestAPIPermissions_CoversEveryProcedure(t *testing.T) {
	iface := reflect.TypeOf((*gateonv1connect.ApiServiceHandler)(nil)).Elem()

	declared := make(map[string]bool, iface.NumMethod())
	for i := range iface.NumMethod() {
		procedure := procedureFor(iface.Method(i).Name)
		declared[procedure] = true
		if _, ok := apiPermissions[procedure]; !ok {
			t.Errorf("%s has no apiPermissions entry; decide what it requires and add one",
				iface.Method(i).Name)
		}
	}

	// The reverse direction: an entry for an RPC that no longer exists is dead
	// weight that reads as coverage.
	for procedure := range apiPermissions {
		if !declared[procedure] {
			t.Errorf("apiPermissions has %s, which ApiService no longer declares", procedure)
		}
	}

	if len(apiPermissions) != iface.NumMethod() {
		t.Errorf("table has %d entries for %d procedures", len(apiPermissions), iface.NumMethod())
	}
}

// spyApiService records whether a service method was reached. Only the methods
// the tests exercise are implemented; the rest come from the embedded
// Unimplemented handler, which is also how api.ConnectHandler is built.
type spyApiService struct {
	gateonv1connect.UnimplementedApiServiceHandler
	mitigateReached bool
	listReached     bool
}

func (s *spyApiService) MitigateThreat(
	_ context.Context, _ *connect.Request[gateonv1.MitigateThreatRequest],
) (*connect.Response[gateonv1.MitigateThreatResponse], error) {
	s.mitigateReached = true
	return connect.NewResponse(&gateonv1.MitigateThreatResponse{}), nil
}

func (s *spyApiService) ListSecurityThreats(
	_ context.Context, _ *connect.Request[gateonv1.ListSecurityThreatsRequest],
) (*connect.Response[gateonv1.ListSecurityThreatsResponse], error) {
	s.listReached = true
	return connect.NewResponse(&gateonv1.ListSecurityThreatsResponse{}), nil
}

// withClaims stands in for PasetoAuth, which is what puts claims on the request
// context in production. All three transports sit behind it, which is why the
// Connect and gRPC paths were authenticated but unauthorized.
func withClaims(next http.Handler, claims *auth.Claims) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), middleware.UserContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func connectTestClient(t *testing.T, svc gateonv1connect.ApiServiceHandler, claims *auth.Claims, guarded bool) gateonv1connect.ApiServiceClient {
	t.Helper()
	var opts []connect.HandlerOption
	if guarded {
		opts = append(opts, connect.WithInterceptors(NewConnectRBACInterceptor()))
	}
	path, h := gateonv1connect.NewApiServiceHandler(svc, opts...)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(withClaims(mux, claims))
	t.Cleanup(srv.Close)
	return gateonv1connect.NewApiServiceClient(srv.Client(), srv.URL)
}

// TestConnectRBAC_ViewerMitigateThreat pins the bug and the fix side by side.
// The unguarded subtest is how run.go mounted the handler before this change:
// a viewer, refused by POST /v1/diagnostics/mitigate, reaches the identical
// svc.MitigateThreat over Connect.
func TestConnectRBAC_ViewerMitigateThreat(t *testing.T) {
	viewer := &auth.Claims{ID: "u-viewer", Username: "viewer", Role: auth.RoleViewer}

	t.Run("unguarded handler lets a viewer mitigate", func(t *testing.T) {
		spy := &spyApiService{}
		client := connectTestClient(t, spy, viewer, false)

		_, err := client.MitigateThreat(context.Background(),
			connect.NewRequest(&gateonv1.MitigateThreatRequest{}))
		if err != nil {
			t.Fatalf("unguarded call should have succeeded, got %v", err)
		}
		if !spy.mitigateReached {
			t.Fatal("expected the service method to be reached with no interceptor")
		}
	})

	t.Run("interceptor denies the viewer and the method never runs", func(t *testing.T) {
		spy := &spyApiService{}
		client := connectTestClient(t, spy, viewer, true)

		_, err := client.MitigateThreat(context.Background(),
			connect.NewRequest(&gateonv1.MitigateThreatRequest{}))
		if err == nil {
			t.Fatal("viewer must not be permitted to mitigate a threat over Connect")
		}
		if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
			t.Fatalf("code = %v, want %v", got, connect.CodePermissionDenied)
		}
		if spy.mitigateReached {
			t.Fatal("MitigateThreat ran despite the permission check failing")
		}
	})

	t.Run("viewer keeps the reads it already had", func(t *testing.T) {
		spy := &spyApiService{}
		client := connectTestClient(t, spy, viewer, true)

		_, err := client.ListSecurityThreats(context.Background(),
			connect.NewRequest(&gateonv1.ListSecurityThreatsRequest{}))
		if err != nil {
			t.Fatalf("viewer holds ActionRead on diagnostics; got %v", err)
		}
		if !spy.listReached {
			t.Fatal("expected the read to reach the service method")
		}
	})

	t.Run("operator may mitigate", func(t *testing.T) {
		spy := &spyApiService{}
		operator := &auth.Claims{ID: "u-op", Username: "op", Role: auth.RoleOperator}
		client := connectTestClient(t, spy, operator, true)

		if _, err := client.MitigateThreat(context.Background(),
			connect.NewRequest(&gateonv1.MitigateThreatRequest{})); err != nil {
			t.Fatalf("operator holds ActionWrite on diagnostics; got %v", err)
		}
		if !spy.mitigateReached {
			t.Fatal("expected the operator's call to reach the service method")
		}
	})
}

// TestGRPCRBAC_UnaryInterceptor covers the surface HandleProxyOrLocal reaches
// on Content-Type. Before this change every one of these calls ran the handler,
// whatever the caller's role.
func TestGRPCRBAC_UnaryInterceptor(t *testing.T) {
	interceptor := NewGRPCRBACInterceptor()

	call := func(role, method string) (bool, error) {
		ctx := context.Background()
		if role != "" {
			ctx = context.WithValue(ctx, middleware.UserContextKey,
				&auth.Claims{ID: "u-" + role, Username: role, Role: role})
		}
		reached := false
		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method},
			func(context.Context, any) (any, error) {
				reached = true
				return nil, nil
			})
		return reached, err
	}

	// The widest part of the gRPC hole: config, routes and TLS were reachable
	// by any authenticated role by setting application/grpc-web.
	updateGlobal := procedureFor("UpdateGlobalConfig")

	t.Run("viewer denied on a global config write", func(t *testing.T) {
		reached, err := call(auth.RoleViewer, updateGlobal)
		if err == nil {
			t.Fatal("a viewer must not rewrite the global config over gRPC")
		}
		if got := status.Code(err); got != codes.PermissionDenied {
			t.Fatalf("code = %v, want %v", got, codes.PermissionDenied)
		}
		if reached {
			t.Fatal("the handler ran despite the permission check failing")
		}
	})

	t.Run("viewer denied on a route write", func(t *testing.T) {
		if _, err := call(auth.RoleViewer, procedureFor("DeleteRoute")); err == nil {
			t.Fatal("a viewer must not delete a route over gRPC")
		}
	})

	t.Run("operator allowed on a global config write", func(t *testing.T) {
		reached, err := call(auth.RoleOperator, updateGlobal)
		if err != nil {
			t.Fatalf("operator holds ActionWrite on global; got %v", err)
		}
		if !reached {
			t.Fatal("expected the operator's call to reach the handler")
		}
	})

	t.Run("viewer allowed on a mapped read", func(t *testing.T) {
		reached, err := call(auth.RoleViewer, procedureFor("ListSecurityThreats"))
		if err != nil {
			t.Fatalf("viewer holds ActionRead on diagnostics; got %v", err)
		}
		if !reached {
			t.Fatal("expected the read to reach the handler")
		}
	})

	t.Run("unknown procedure denied even for an admin", func(t *testing.T) {
		if _, err := call(auth.RoleAdmin, procedureFor("SomeRpcAddedLater")); err == nil {
			t.Fatal("an unmapped procedure must fail closed")
		}
	})

	t.Run("auth disabled still serves", func(t *testing.T) {
		if _, err := call("", updateGlobal); err != nil {
			t.Fatalf("no claims means PasetoAuth never ran; got %v", err)
		}
	})
}

// TestGRPCRBAC_ClaimsReachTheInterceptor guards the assumption the gRPC half
// rests on: grpc-go's ServeHTTP transport roots the stream context at
// r.Context(), so the claims PasetoAuth set survive. If that stopped holding,
// claimsFrom would see nil and silently read as "auth disabled".
func TestGRPCRBAC_ClaimsReachTheInterceptor(t *testing.T) {
	viewer := &auth.Claims{ID: "u-viewer", Username: "viewer", Role: auth.RoleViewer}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, viewer)

	claims, err := claimsFrom(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims == nil || claims.Role != auth.RoleViewer {
		t.Fatalf("claims = %+v, want the viewer's", claims)
	}
}

func TestAuthorizeProcedure(t *testing.T) {
	const peerAddr = "203.0.113.7:44212"

	claims := func(role string) context.Context {
		return context.WithValue(context.Background(), middleware.UserContextKey,
			&auth.Claims{ID: "u-" + role, Username: role, Role: role})
	}

	tests := []struct {
		name      string
		ctx       context.Context
		procedure string
		wantErr   bool
	}{
		// The three writes a viewer could reach over Connect and not over REST.
		{"viewer denied mitigate", claims(auth.RoleViewer), procedureFor("MitigateThreat"), true},
		{"viewer denied remove mitigation", claims(auth.RoleViewer), procedureFor("RemoveMitigatedThreat"), true},
		{"viewer denied apply recommendation", claims(auth.RoleViewer), procedureFor("ApplyRecommendation"), true},

		// Writes across the other resources, reachable over gRPC by any role.
		{"viewer denied route delete", claims(auth.RoleViewer), procedureFor("DeleteRoute"), true},
		{"viewer denied tls write", claims(auth.RoleViewer), procedureFor("UpdateTLSOption"), true},
		{"viewer denied clamav uninstall", claims(auth.RoleViewer), procedureFor("UninstallClamav"), true},
		{"viewer denied waf rule create", claims(auth.RoleViewer), procedureFor("CreateWafRule"), true},
		{"operator denied user write", claims(auth.RoleOperator), procedureFor("UpdateUser"), true},

		{"viewer allowed threats read", claims(auth.RoleViewer), procedureFor("ListSecurityThreats"), false},
		{"viewer allowed audit read", claims(auth.RoleViewer), procedureFor("ListAuditLogs"), false},
		{"viewer allowed traces read", claims(auth.RoleViewer), procedureFor("ListTraces"), false},
		{"viewer allowed routes read", claims(auth.RoleViewer), procedureFor("ListRoutes"), false},

		{"operator allowed mitigate", claims(auth.RoleOperator), procedureFor("MitigateThreat"), false},
		{"operator allowed route write", claims(auth.RoleOperator), procedureFor("UpdateRoute"), false},
		{"admin allowed user write", claims(auth.RoleAdmin), procedureFor("UpdateUser"), false},

		// Self-service: ApiService applies the self-or-admin rule itself, so
		// denying a viewer here would stop them changing their own password.
		{"viewer allowed change password", claims(auth.RoleViewer), procedureFor("ChangePassword"), false},

		// Public procedures are served before authentication by the base
		// handler, so denying them here would break first-run setup and login.
		{"login is public", context.Background(), procedureFor("Login"), false},
		{"setup is public", context.Background(), procedureFor("Setup"), false},

		// Auth disabled: PasetoAuth never ran, matching handlers.RequirePermission.
		{"no claims allows", context.Background(), procedureFor("MitigateThreat"), false},

		// Fails closed.
		{"unmapped denied", claims(auth.RoleAdmin), procedureFor("SomeRpcAddedLater"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := authorizeProcedure(tt.ctx, tt.procedure, peerAddr)
			if tt.wantErr && err == nil {
				t.Fatalf("%s: expected denial", tt.procedure)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("%s: unexpected denial: %v", tt.procedure, err)
			}
		})
	}
}
