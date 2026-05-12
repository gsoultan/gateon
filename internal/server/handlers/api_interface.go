package handlers

import (
	"context"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// GlobalAndAuthAPI defines the API surface needed by global and auth REST handlers.
// Implementations (e.g. *api.ApiService) provide global config and auth operations.
// Use this interface for testability via mock injection.
type GlobalAndAuthAPI interface {
	GetGlobals() config.GlobalConfigStore
	GetTLSManager() tls.TLSManager
	GetEbpfManager() ebpf.Manager
	GetClamAVStatus(ctx context.Context) bool
	IsSetupRequired(ctx context.Context, req *gateonv1.IsSetupRequiredRequest) (*gateonv1.IsSetupRequiredResponse, error)
	Setup(ctx context.Context, req *gateonv1.SetupRequest) (*gateonv1.SetupResponse, error)
	Login(ctx context.Context, req *gateonv1.LoginRequest) (*gateonv1.LoginResponse, error)
	ListUsers(ctx context.Context, req *gateonv1.ListUsersRequest) (*gateonv1.ListUsersResponse, error)
	UpdateUser(ctx context.Context, req *gateonv1.UpdateUserRequest) (*gateonv1.UpdateUserResponse, error)
	DeleteUser(ctx context.Context, req *gateonv1.DeleteUserRequest) (*gateonv1.DeleteUserResponse, error)
	ChangePassword(ctx context.Context, req *gateonv1.ChangePasswordRequest) (*gateonv1.ChangePasswordResponse, error)
	GetDiagnostics(ctx context.Context, req *gateonv1.GetDiagnosticsRequest) (*gateonv1.GetDiagnosticsResponse, error)
	ApplyRecommendation(ctx context.Context, req *gateonv1.ApplyRecommendationRequest) (*gateonv1.ApplyRecommendationResponse, error)
	TraceRoute(ctx context.Context, req *gateonv1.TraceRouteRequest) (*gateonv1.TraceRouteResponse, error)
	ListSecurityThreats(ctx context.Context, req *gateonv1.ListSecurityThreatsRequest) (*gateonv1.ListSecurityThreatsResponse, error)
	ListReputations(ctx context.Context, req *gateonv1.ListReputationsRequest) (*gateonv1.ListReputationsResponse, error)
	RemoveMitigatedThreat(ctx context.Context, req *gateonv1.RemoveMitigatedThreatRequest) (*gateonv1.RemoveMitigatedThreatResponse, error)
	GetCloudflareIPs(ctx context.Context, req *gateonv1.GetCloudflareIPsRequest) (*gateonv1.GetCloudflareIPsResponse, error)
	TriggerWafUpdate(ctx context.Context, req *gateonv1.TriggerWafUpdateRequest) (*gateonv1.TriggerWafUpdateResponse, error)
	InstallClamav(ctx context.Context, req *gateonv1.InstallClamavRequest) (*gateonv1.InstallClamavResponse, error)
	RunDeepScan(ctx context.Context, req *gateonv1.RunDeepScanRequest) (*gateonv1.RunDeepScanResponse, error)
	Setup2FA(ctx context.Context, req *gateonv1.Setup2FARequest) (*gateonv1.Setup2FAResponse, error)
	Verify2FA(ctx context.Context, req *gateonv1.Verify2FARequest) (*gateonv1.Verify2FAResponse, error)
}
