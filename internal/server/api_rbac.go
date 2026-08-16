// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/proto/gateon/v1/gateonv1connect"
)

// Authorization for the management API was written into the REST handlers, as
// handlers.RequirePermission(w, r, action, resource). That signature cannot be
// called from a ConnectRPC or gRPC handler, so the two other transports served
// the same ApiService methods with no permission check at all — silently,
// because dropping a check that takes an http.ResponseWriter does not fail to
// compile.
//
// Authentication was never the gap. base_handler_auth.go names both /v1/ and
// /gateon.v1. in every predicate, so all three transports sit behind PasetoAuth
// and arrive here with claims on the context. Nothing was reading them.
//
// Two distinct holes existed:
//
//   - ConnectRPC. api.ConnectHandler is mounted on the mux. A viewer refused by
//     POST /v1/diagnostics/mitigate was accepted by
//     /gateon.v1.ApiService/MitigateThreat — the same svc.MitigateThreat call.
//
//   - gRPC and gRPC-Web. run.go registers the *entire* ApiService on a
//     grpc.Server, and HandleProxyOrLocal dispatches to it on Content-Type
//     before the mux is ever consulted. Any authenticated principal of any role
//     could reach every RPC by sending application/grpc-web. The privilege
//     escalation was selectable by a header.
//
// apiPermissions is the single table both transports enforce, so they cannot
// drift apart again. It is exhaustive over ApiService by construction:
// TestAPIPermissions_CoversEveryProcedure reflects over the generated handler
// interface and fails if any RPC is missing an entry. A procedure with no entry
// is denied, so a new RPC fails closed until someone decides what it needs.

type permKind int

const (
	// permRBAC consults auth.Allowed with the action and resource below.
	permRBAC permKind = iota
	// permPublic is served before authentication by the base handler
	// (isPublicAuthPath / isLoginPath), so it must not be denied here.
	permPublic
	// permAuthenticated requires a caller but no specific permission, because
	// ApiService itself applies a finer rule this table cannot express.
	permAuthenticated
)

type apiPermission struct {
	kind     permKind
	action   auth.Action
	resource auth.Resource
}

func readOn(r auth.Resource) apiPermission {
	return apiPermission{kind: permRBAC, action: auth.ActionRead, resource: r}
}

func writeOn(r auth.Resource) apiPermission {
	return apiPermission{kind: permRBAC, action: auth.ActionWrite, resource: r}
}

var (
	publicProc        = apiPermission{kind: permPublic}
	authenticatedProc = apiPermission{kind: permAuthenticated}
)

var (
	errUnmappedProcedure       = errors.New("procedure has no permission mapping")
	errPermissionDenied        = errors.New("permission denied")
	errInsufficientPermissions = errors.New("insufficient permissions")
)

// apiPermissions maps every ApiService procedure to the permission its REST
// twin enforces. Keyed by the generated procedure constants rather than path
// strings, so a renamed RPC breaks the build instead of quietly falling through
// to the unmapped case.
var apiPermissions = map[string]apiPermission{
	// Served before authentication by the base handler.
	gateonv1connect.ApiServiceLoginProcedure:           publicProc,
	gateonv1connect.ApiServiceSetupProcedure:           publicProc,
	gateonv1connect.ApiServiceIsSetupRequiredProcedure: publicProc,

	// ApiService.ChangePassword refuses to change another user's password
	// unless the caller is an admin (internal/api/users.go). Requiring a
	// resource permission here would instead stop an operator or viewer from
	// changing their own.
	gateonv1connect.ApiServiceChangePasswordProcedure: authenticatedProc,

	// Routes. PUT/DELETE /v1/routes.
	gateonv1connect.ApiServiceListRoutesProcedure:  readOn(auth.ResourceRoutes),
	gateonv1connect.ApiServiceUpdateRouteProcedure: writeOn(auth.ResourceRoutes),
	gateonv1connect.ApiServiceDeleteRouteProcedure: writeOn(auth.ResourceRoutes),

	// Services. Both discovery RPCs probe a target the caller names, which is
	// why POST /v1/discover/grpc requires write rather than read; DiscoverTech
	// has no REST twin and is mapped to match its sibling.
	gateonv1connect.ApiServiceListServicesProcedure:         readOn(auth.ResourceServices),
	gateonv1connect.ApiServiceUpdateServiceProcedure:        writeOn(auth.ResourceServices),
	gateonv1connect.ApiServiceDeleteServiceProcedure:        writeOn(auth.ResourceServices),
	gateonv1connect.ApiServiceDiscoverGrpcServicesProcedure: writeOn(auth.ResourceServices),
	gateonv1connect.ApiServiceDiscoverTechProcedure:         writeOn(auth.ResourceServices),

	// Entrypoints. PUT/DELETE /v1/entryPoints.
	gateonv1connect.ApiServiceListEntryPointsProcedure:  readOn(auth.ResourceEntryPoints),
	gateonv1connect.ApiServiceUpdateEntryPointProcedure: writeOn(auth.ResourceEntryPoints),
	gateonv1connect.ApiServiceDeleteEntryPointProcedure: writeOn(auth.ResourceEntryPoints),

	// Middlewares. GetCloudflareIPs feeds the Cloudflare trust list, which is
	// middleware configuration; GET /v1/geoip/status uses the same resource.
	gateonv1connect.ApiServiceListMiddlewaresProcedure:  readOn(auth.ResourceMiddlewares),
	gateonv1connect.ApiServiceUpdateMiddlewareProcedure: writeOn(auth.ResourceMiddlewares),
	gateonv1connect.ApiServiceDeleteMiddlewareProcedure: writeOn(auth.ResourceMiddlewares),
	gateonv1connect.ApiServiceGetCloudflareIPsProcedure: readOn(auth.ResourceMiddlewares),

	// TLS options. PUT/DELETE /v1/tls-options.
	gateonv1connect.ApiServiceListTLSOptionsProcedure:  readOn(auth.ResourceTLSOptions),
	gateonv1connect.ApiServiceUpdateTLSOptionProcedure: writeOn(auth.ResourceTLSOptions),
	gateonv1connect.ApiServiceDeleteTLSOptionProcedure: writeOn(auth.ResourceTLSOptions),

	// Global config. POST/PUT /v1/global, via handleUpdateGlobal.
	gateonv1connect.ApiServiceGetGlobalConfigProcedure:    readOn(auth.ResourceGlobal),
	gateonv1connect.ApiServiceUpdateGlobalConfigProcedure: writeOn(auth.ResourceGlobal),

	// Users. ApiService additionally requires admin on all three
	// (internal/api/users.go); this keeps the transport check aligned with
	// GET/PUT/DELETE /v1/users rather than relying on that alone.
	gateonv1connect.ApiServiceListUsersProcedure:  readOn(auth.ResourceUsers),
	gateonv1connect.ApiServiceUpdateUserProcedure: writeOn(auth.ResourceUsers),
	gateonv1connect.ApiServiceDeleteUserProcedure: writeOn(auth.ResourceUsers),

	// Diagnostics reads. GET /v1/status, /v1/diagnostics, /v1/audit/*,
	// /v1/diag/security-threats, /v1/security/reputations, /v1/traces.
	gateonv1connect.ApiServiceGetStatusProcedure:           readOn(auth.ResourceDiagnostics),
	gateonv1connect.ApiServiceGetDiagnosticsProcedure:      readOn(auth.ResourceDiagnostics),
	gateonv1connect.ApiServiceListSecurityThreatsProcedure: readOn(auth.ResourceDiagnostics),
	gateonv1connect.ApiServiceGetSecurityThreatProcedure:   readOn(auth.ResourceDiagnostics),
	gateonv1connect.ApiServiceListReputationsProcedure:     readOn(auth.ResourceDiagnostics),
	gateonv1connect.ApiServiceListAuditLogsProcedure:       readOn(auth.ResourceDiagnostics),
	gateonv1connect.ApiServiceListAuditArchivesProcedure:   readOn(auth.ResourceDiagnostics),
	gateonv1connect.ApiServiceGetAuditArchiveProcedure:     readOn(auth.ResourceDiagnostics),
	gateonv1connect.ApiServiceListTracesProcedure:          readOn(auth.ResourceDiagnostics),
	gateonv1connect.ApiServiceGetTraceProcedure:            readOn(auth.ResourceDiagnostics),

	// TraceRoute and ValidateCORS reach outward but are mapped read, matching
	// POST /v1/diagnostics/traceroute and /v1/diagnostics/cors-validator.
	gateonv1connect.ApiServiceTraceRouteProcedure:   readOn(auth.ResourceDiagnostics),
	gateonv1connect.ApiServiceValidateCORSProcedure: readOn(auth.ResourceDiagnostics),

	// Diagnostics writes. These three are what a viewer could reach over
	// Connect and not over REST.
	gateonv1connect.ApiServiceMitigateThreatProcedure:        writeOn(auth.ResourceDiagnostics),
	gateonv1connect.ApiServiceRemoveMitigatedThreatProcedure: writeOn(auth.ResourceDiagnostics),
	gateonv1connect.ApiServiceApplyRecommendationProcedure:   writeOn(auth.ResourceDiagnostics),

	// Host-level security controls. All four mirror /v1/security/clamav/* and
	// /v1/waf/update, which are guarded on the global resource because they
	// change the posture of the host the gateway runs on.
	gateonv1connect.ApiServiceInstallClamavProcedure:       writeOn(auth.ResourceGlobal),
	gateonv1connect.ApiServiceUninstallClamavProcedure:     writeOn(auth.ResourceGlobal),
	gateonv1connect.ApiServiceRunDeepScanProcedure:         writeOn(auth.ResourceGlobal),
	gateonv1connect.ApiServiceGetClamavScanStatusProcedure: readOn(auth.ResourceGlobal),
	gateonv1connect.ApiServiceTriggerWafUpdateProcedure:    writeOn(auth.ResourceGlobal),

	// WAF rules. GET/POST/PUT/DELETE /v1/waf/rules.
	gateonv1connect.ApiServiceListWafRulesProcedure:  readOn(auth.ResourceWafRules),
	gateonv1connect.ApiServiceCreateWafRuleProcedure: writeOn(auth.ResourceWafRules),
	gateonv1connect.ApiServiceUpdateWafRuleProcedure: writeOn(auth.ResourceWafRules),
	gateonv1connect.ApiServiceDeleteWafRuleProcedure: writeOn(auth.ResourceWafRules),
}

// NewConnectRBACInterceptor guards the ConnectRPC handler mounted on the mux.
func NewConnectRBACInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if err := authorizeProcedure(ctx, req.Spec().Procedure, req.Peer().Addr); err != nil {
				return nil, connect.NewError(connect.CodePermissionDenied, err)
			}
			return next(ctx, req)
		}
	}
}

// NewGRPCRBACInterceptor guards the grpc.Server that HandleProxyOrLocal reaches
// for application/grpc and application/grpc-web, which never touches the mux
// and so is not covered by the Connect interceptor. ApiService declares no
// streaming RPCs, so a unary interceptor covers all of it.
func NewGRPCRBACInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := authorizeProcedure(ctx, info.FullMethod, grpcPeerAddr(ctx)); err != nil {
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
		return handler(ctx, req)
	}
}

func grpcPeerAddr(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return p.Addr.String()
	}
	return ""
}

// authorizeProcedure answers whether the caller in ctx may invoke procedure. It
// returns a sentinel error rather than a transport error so the Connect and
// gRPC interceptors can each render it in their own code space.
func authorizeProcedure(ctx context.Context, procedure, peerAddr string) error {
	perm, mapped := apiPermissions[procedure]
	if !mapped {
		logger.L.LogWarn("procedure has no permission mapping; denying",
			"event", "rbac_permission_denied", "procedure", procedure, "peer", peerAddr)
		return errUnmappedProcedure
	}
	if perm.kind == permPublic {
		return nil
	}

	// Mirrors handlers.RequirePermission: no claims means PasetoAuth never ran,
	// i.e. auth is disabled for this deployment. Diverging here would make the
	// transports enforce differently again, in the opposite direction.
	claims, err := claimsFrom(ctx)
	if err != nil || claims == nil {
		return err
	}
	if perm.kind == permAuthenticated {
		return nil
	}

	if !auth.Allowed(ctx, claims.Role, perm.action, perm.resource) {
		logDenied(procedure, peerAddr, claims, string(perm.action), string(perm.resource))
		return errInsufficientPermissions
	}
	return nil
}

// claimsFrom returns the caller's claims, or (nil, nil) when auth is disabled.
func claimsFrom(ctx context.Context) (*auth.Claims, error) {
	claimsVal := ctx.Value(middleware.UserContextKey)
	if claimsVal == nil {
		return nil, nil
	}
	claims, ok := claimsVal.(*auth.Claims)
	if !ok || claims == nil {
		return nil, errPermissionDenied
	}
	return claims, nil
}

func logDenied(procedure, peerAddr string, claims *auth.Claims, action, resource string) {
	logger.L.LogWarn("RBAC permission denied",
		"event", "rbac_permission_denied",
		"procedure", procedure,
		"peer", peerAddr,
		"user_id", claims.ID,
		"role", claims.Role,
		"action", action,
		"resource", resource,
	)
}
