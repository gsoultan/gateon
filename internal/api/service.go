package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/domain"
	"github.com/gsoultan/gateon/internal/telemetry"
	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
)

type ApiService struct {
	gateonv1.UnimplementedApiServiceServer
	Version            string
	Routes             config.RouteStore
	Services           config.ServiceStore
	Globals            config.GlobalConfigStore
	EntryPoints        config.EntryPointStore
	Middlewares        config.MiddlewareStore
	TLSOptions         config.TLSOptionStore
	Auth               auth.Service
	Invalidator        domain.ProxyInvalidator
	TLSManager         gtls.TLSManager
	RouteStatsProvider RouteStatsProvider
}

// GetGlobals returns the global config store for REST handlers.
func (s *ApiService) GetGlobals() config.GlobalConfigStore {
	return s.Globals
}

func (s *ApiService) GetTLSManager() gtls.TLSManager {
	return s.TLSManager
}

// NewApiService creates an ApiService from config (Factory pattern).
func NewApiService(cfg ApiServiceConfig) *ApiService {
	return &ApiService{
		Version:            cfg.Version,
		Routes:             cfg.Routes,
		Services:           cfg.Services,
		Globals:            cfg.Globals,
		EntryPoints:        cfg.EntryPoints,
		Middlewares:        cfg.Middlewares,
		TLSOptions:         cfg.TLSOptions,
		Auth:               cfg.Auth,
		Invalidator:        cfg.Invalidator,
		TLSManager:         cfg.TLSManager,
		RouteStatsProvider: cfg.RouteStatsProvider,
	}
}

func (s *ApiService) ListEntryPoints(ctx context.Context, _ *gateonv1.ListEntryPointsRequest) (*gateonv1.ListEntryPointsResponse, error) {
	if s.EntryPoints == nil {
		return &gateonv1.ListEntryPointsResponse{EntryPoints: nil}, nil
	}
	return &gateonv1.ListEntryPointsResponse{EntryPoints: s.EntryPoints.List(ctx)}, nil
}

func (s *ApiService) UpdateEntryPoint(ctx context.Context, req *gateonv1.UpdateEntryPointRequest) (*gateonv1.UpdateEntryPointResponse, error) {
	if s.EntryPoints == nil || req == nil || req.EntryPoint == nil {
		return &gateonv1.UpdateEntryPointResponse{Success: false}, nil
	}
	if err := s.EntryPoints.Update(ctx, req.EntryPoint); err != nil {
		return &gateonv1.UpdateEntryPointResponse{Success: false}, err
	}
	return &gateonv1.UpdateEntryPointResponse{Success: true}, nil
}

func (s *ApiService) DeleteEntryPoint(ctx context.Context, req *gateonv1.DeleteEntryPointRequest) (*gateonv1.DeleteEntryPointResponse, error) {
	if s.EntryPoints == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteEntryPointResponse{Success: false}, nil
	}
	if err := s.EntryPoints.Delete(ctx, req.Id); err != nil {
		return &gateonv1.DeleteEntryPointResponse{Success: false}, err
	}
	return &gateonv1.DeleteEntryPointResponse{Success: true}, nil
}

func (s *ApiService) GetStatus(ctx context.Context, _ *gateonv1.GetStatusRequest) (*gateonv1.GetStatusResponse, error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	routesCount := 0
	if s.Routes != nil {
		routesCount = len(s.Routes.List(ctx))
	}
	servicesCount := 0
	if s.Services != nil {
		servicesCount = len(s.Services.List(ctx))
	}
	entryPointsCount := 0
	if s.EntryPoints != nil {
		entryPointsCount = len(s.EntryPoints.List(ctx))
	}
	middlewaresCount := 0
	if s.Middlewares != nil {
		middlewaresCount = len(s.Middlewares.List(ctx))
	}

	stats := telemetry.GetSystemStats()

	return &gateonv1.GetStatusResponse{
		Status:             "running",
		Version:            s.Version,
		Uptime:             int64(time.Since(telemetry.GetStartTime()).Seconds()),
		MemoryUsage:        int64(m.Alloc),
		RoutesCount:        int32(routesCount),
		ServicesCount:      int32(servicesCount),
		EntryPointsCount:   int32(entryPointsCount),
		MiddlewaresCount:   int32(middlewaresCount),
		CpuUsage:           stats.CPUUsage,
		MemoryUsagePercent: stats.MemoryUsagePercent,
	}, nil
}

func (s *ApiService) ListTraces(ctx context.Context, req *gateonv1.ListTracesRequest) (*gateonv1.ListTracesResponse, error) {
	if req == nil {
		return nil, errors.New("request is required")
	}
	traces := telemetry.GetTraces(ctx, int(req.Limit))
	res := make([]*gateonv1.Trace, 0, len(traces))
	for _, t := range traces {
		res = append(res, &gateonv1.Trace{
			Id:            t.ID,
			OperationName: t.OperationName,
			ServiceName:   t.ServiceName,
			DurationMs:    t.DurationMs,
			Timestamp:     t.Timestamp.Format(time.RFC3339),
			Status:        t.Status,
			Path:          t.Path,
		})
	}
	return &gateonv1.ListTracesResponse{Traces: res}, nil
}

func (s *ApiService) ListRoutes(ctx context.Context, _ *gateonv1.ListRoutesRequest) (*gateonv1.ListRoutesResponse, error) {
	if s.Routes == nil {
		return &gateonv1.ListRoutesResponse{Routes: nil}, nil
	}
	return &gateonv1.ListRoutesResponse{Routes: s.Routes.List(ctx)}, nil
}

func (s *ApiService) UpdateRoute(ctx context.Context, req *gateonv1.UpdateRouteRequest) (*gateonv1.UpdateRouteResponse, error) {
	if s.Routes == nil || req == nil || req.Route == nil {
		return &gateonv1.UpdateRouteResponse{Success: false}, nil
	}
	if err := s.Routes.Update(ctx, req.Route); err != nil {
		return &gateonv1.UpdateRouteResponse{Success: false}, err
	}
	return &gateonv1.UpdateRouteResponse{Success: true}, nil
}

func (s *ApiService) DeleteRoute(ctx context.Context, req *gateonv1.DeleteRouteRequest) (*gateonv1.DeleteRouteResponse, error) {
	if s.Routes == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteRouteResponse{Success: false}, nil
	}
	if err := s.Routes.Delete(ctx, req.Id); err != nil {
		return &gateonv1.DeleteRouteResponse{Success: false}, err
	}
	return &gateonv1.DeleteRouteResponse{Success: true}, nil
}

func (s *ApiService) ListServices(ctx context.Context, _ *gateonv1.ListServicesRequest) (*gateonv1.ListServicesResponse, error) {
	if s.Services == nil {
		return &gateonv1.ListServicesResponse{Services: nil}, nil
	}
	return &gateonv1.ListServicesResponse{Services: s.Services.List(ctx)}, nil
}

func (s *ApiService) UpdateService(ctx context.Context, req *gateonv1.UpdateServiceRequest) (*gateonv1.UpdateServiceResponse, error) {
	if s.Services == nil || req == nil || req.Service == nil {
		return &gateonv1.UpdateServiceResponse{Success: false}, nil
	}
	if err := s.Services.Update(ctx, req.Service); err != nil {
		return &gateonv1.UpdateServiceResponse{Success: false}, err
	}
	return &gateonv1.UpdateServiceResponse{Success: true}, nil
}

func (s *ApiService) DeleteService(ctx context.Context, req *gateonv1.DeleteServiceRequest) (*gateonv1.DeleteServiceResponse, error) {
	if s.Services == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteServiceResponse{Success: false}, nil
	}
	if err := s.Services.Delete(ctx, req.Id); err != nil {
		return &gateonv1.DeleteServiceResponse{Success: false}, err
	}
	return &gateonv1.DeleteServiceResponse{Success: true}, nil
}

func (s *ApiService) DiscoverGrpcServices(ctx context.Context, req *gateonv1.DiscoverGrpcServicesRequest) (*gateonv1.DiscoverGrpcServicesResponse, error) {
	if req == nil {
		return nil, errors.New("request is required")
	}
	if req.Url == "" {
		return nil, errors.New("url is required")
	}

	host := req.Url
	useTLS := false
	if strings.HasPrefix(req.Url, "h2c://") {
		host = strings.TrimPrefix(req.Url, "h2c://")
	} else if strings.HasPrefix(req.Url, "h2://") {
		host = strings.TrimPrefix(req.Url, "h2://")
		useTLS = true
	} else if strings.HasPrefix(req.Url, "h3://") {
		host = strings.TrimPrefix(req.Url, "h3://")
		useTLS = true
	}

	// SSRF prevention: validate host
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	if h == "localhost" || h == "127.0.0.1" || h == "::1" {
		return nil, errors.New("access to localhost is forbidden")
	}

	var opts []grpc.DialOption
	if useTLS {
		tlsCfg, err := gtls.CreateTLSClientConfig(req.TlsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create tls config: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, host, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", host, err)
	}
	defer conn.Close()

	client := grpc_reflection_v1alpha.NewServerReflectionClient(conn)
	stream, err := client.ServerReflectionInfo(dialCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create reflection stream: %w", err)
	}

	if err := stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_ListServices{
			ListServices: "*",
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to send reflection request: %w", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed to receive reflection response: %w", err)
	}

	listResp := resp.GetListServicesResponse()
	if listResp == nil {
		return nil, errors.New("no services found")
	}

	var services []string
	for _, svc := range listResp.Service {
		// Filter out standard reflection and health check services if desired
		if svc.Name != "grpc.reflection.v1alpha.ServerReflection" &&
			svc.Name != "grpc.reflection.v1.ServerReflection" &&
			svc.Name != "grpc.health.v1.Health" {
			services = append(services, svc.Name)
		}
	}

	return &gateonv1.DiscoverGrpcServicesResponse{Services: services}, nil
}

func (s *ApiService) GetGlobalConfig(ctx context.Context, _ *gateonv1.GetGlobalConfigRequest) (*gateonv1.GlobalConfig, error) {
	if s.Globals == nil {
		return &gateonv1.GlobalConfig{}, nil
	}
	return s.Globals.Get(ctx), nil
}

func (s *ApiService) UpdateGlobalConfig(ctx context.Context, req *gateonv1.UpdateGlobalConfigRequest) (*gateonv1.UpdateGlobalConfigResponse, error) {
	if s.Globals == nil || req == nil || req.Config == nil {
		return &gateonv1.UpdateGlobalConfigResponse{Success: false}, nil
	}

	// Validate config
	if req.Config.Redis != nil && req.Config.Redis.Enabled && req.Config.Redis.Addr == "" {
		return &gateonv1.UpdateGlobalConfigResponse{Success: false}, errors.New("redis address is required when enabled")
	}
	if req.Config.Otel != nil && req.Config.Otel.Enabled && req.Config.Otel.Endpoint == "" {
		return &gateonv1.UpdateGlobalConfigResponse{Success: false}, errors.New("otel endpoint is required when enabled")
	}
	if req.Config.Tls != nil && req.Config.Tls.Acme != nil && req.Config.Tls.Acme.Enabled {
		if req.Config.Tls.Acme.Email == "" {
			return &gateonv1.UpdateGlobalConfigResponse{Success: false}, errors.New("acme email is required when enabled")
		}
	}

	if err := s.Globals.Update(ctx, req.Config); err != nil {
		return &gateonv1.UpdateGlobalConfigResponse{Success: false}, err
	}
	if s.Invalidator != nil {
		s.Invalidator.InvalidateTLS()
		// If TLS config changed, it might affect all routes
		s.Invalidator.InvalidateRoutes(func(*gateonv1.Route) bool { return true })
	}
	return &gateonv1.UpdateGlobalConfigResponse{Success: true}, nil
}

func (s *ApiService) ListMiddlewares(ctx context.Context, _ *gateonv1.ListMiddlewaresRequest) (*gateonv1.ListMiddlewaresResponse, error) {
	if s.Middlewares == nil {
		return &gateonv1.ListMiddlewaresResponse{Middlewares: nil}, nil
	}
	return &gateonv1.ListMiddlewaresResponse{Middlewares: s.Middlewares.List(ctx)}, nil
}

func (s *ApiService) UpdateMiddleware(ctx context.Context, req *gateonv1.UpdateMiddlewareRequest) (*gateonv1.UpdateMiddlewareResponse, error) {
	if s.Middlewares == nil || req == nil || req.Middleware == nil {
		return &gateonv1.UpdateMiddlewareResponse{Success: false}, nil
	}
	if err := s.Middlewares.Update(ctx, req.Middleware); err != nil {
		return &gateonv1.UpdateMiddlewareResponse{Success: false}, err
	}
	return &gateonv1.UpdateMiddlewareResponse{Success: true}, nil
}

func (s *ApiService) DeleteMiddleware(ctx context.Context, req *gateonv1.DeleteMiddlewareRequest) (*gateonv1.DeleteMiddlewareResponse, error) {
	if s.Middlewares == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteMiddlewareResponse{Success: false}, nil
	}
	if err := s.Middlewares.Delete(ctx, req.Id); err != nil {
		return &gateonv1.DeleteMiddlewareResponse{Success: false}, err
	}
	return &gateonv1.DeleteMiddlewareResponse{Success: true}, nil
}

func (s *ApiService) ListTLSOptions(ctx context.Context, _ *gateonv1.ListTLSOptionsRequest) (*gateonv1.ListTLSOptionsResponse, error) {
	if s.TLSOptions == nil {
		return &gateonv1.ListTLSOptionsResponse{TlsOptions: nil}, nil
	}
	return &gateonv1.ListTLSOptionsResponse{TlsOptions: s.TLSOptions.List(ctx)}, nil
}

func (s *ApiService) UpdateTLSOption(ctx context.Context, req *gateonv1.UpdateTLSOptionRequest) (*gateonv1.UpdateTLSOptionResponse, error) {
	if s.TLSOptions == nil || req == nil || req.TlsOption == nil {
		return &gateonv1.UpdateTLSOptionResponse{Success: false}, nil
	}
	if err := s.TLSOptions.Update(ctx, req.TlsOption); err != nil {
		return &gateonv1.UpdateTLSOptionResponse{Success: false}, err
	}
	return &gateonv1.UpdateTLSOptionResponse{Success: true}, nil
}

func (s *ApiService) DeleteTLSOption(ctx context.Context, req *gateonv1.DeleteTLSOptionRequest) (*gateonv1.DeleteTLSOptionResponse, error) {
	if s.TLSOptions == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteTLSOptionResponse{Success: false}, nil
	}
	if err := s.TLSOptions.Delete(ctx, req.Id); err != nil {
		return &gateonv1.DeleteTLSOptionResponse{Success: false}, err
	}
	return &gateonv1.DeleteTLSOptionResponse{Success: true}, nil
}

func (s *ApiService) Login(_ context.Context, req *gateonv1.LoginRequest) (*gateonv1.LoginResponse, error) {
	if req == nil {
		return nil, errors.New("request is required")
	}
	if s.Auth == nil {
		return &gateonv1.LoginResponse{}, nil
	}
	token, user, err := s.Auth.Authenticate(req.Username, req.Password)
	if err != nil {
		return nil, err
	}
	return &gateonv1.LoginResponse{Token: token, User: user}, nil
}

func (s *ApiService) IsSetupRequired(ctx context.Context, _ *gateonv1.IsSetupRequiredRequest) (*gateonv1.IsSetupRequiredResponse, error) {
	// First run: no global.json file — setup required
	if s.Globals != nil && !s.Globals.ConfigFileExists() {
		return &gateonv1.IsSetupRequiredResponse{Required: true}, nil
	}
	if s.Auth == nil {
		return &gateonv1.IsSetupRequiredResponse{Required: true}, nil
	}

	// Setup is required if:
	// 1. No users exist in the database.
	// 2. OR Paseto Secret is still the default one.

	setupDone := s.Auth.IsSetupDone()

	pasetoSecret := ""
	if s.Globals != nil {
		conf := s.Globals.Get(ctx)
		if conf != nil && conf.Auth != nil {
			pasetoSecret = conf.Auth.PasetoSecret
		}
	}

	required := !setupDone || pasetoSecret == ""

	return &gateonv1.IsSetupRequiredResponse{Required: required}, nil
}

func (s *ApiService) Setup(ctx context.Context, req *gateonv1.SetupRequest) (*gateonv1.SetupResponse, error) {
	if req == nil {
		return &gateonv1.SetupResponse{Success: false, Error: "request is required"}, nil
	}
	// Check if setup is already done
	setupReq, err := s.IsSetupRequired(ctx, &gateonv1.IsSetupRequiredRequest{})
	if err == nil && !setupReq.Required {
		return &gateonv1.SetupResponse{Success: false, Error: "setup already completed"}, nil
	}

	if s.Auth == nil {
		// Initialize Auth Manager if it doesn't exist
		databaseURL := "gateon.db"
		if s.Globals != nil {
			conf := s.Globals.Get(ctx)
			if conf != nil && conf.Auth != nil {
				databaseURL = db.AuthDatabaseURL(conf.Auth)
			}
		}

		mgr, err := auth.NewManager(databaseURL, req.PasetoSecret)
		if err != nil {
			return &gateonv1.SetupResponse{Success: false, Error: "failed to initialize auth manager: " + err.Error()}, nil
		}
		s.Auth = mgr
	}

	// 1. Create/Update Admin User
	// Reuse the existing user's ID when the username already exists so that
	// ON CONFLICT(id) correctly updates the row instead of failing on the
	// UNIQUE constraint for username.
	admin := &gateonv1.User{
		Username: req.AdminUsername,
		Password: req.AdminPassword,
		Role:     auth.RoleAdmin,
	}
	if existing, _, _ := s.Auth.ListUsers(0, 1000, admin.Username); len(existing) > 0 {
		for _, u := range existing {
			if u.Username == admin.Username {
				admin.Id = u.Id
				break
			}
		}
	}
	if err := s.Auth.UpsertUser(admin); err != nil {
		return &gateonv1.SetupResponse{Success: false, Error: "failed to create admin: " + err.Error()}, nil
	}

	// 2. Update Global Config (Paseto Secret and Management Settings)
	conf := s.Globals.Get(ctx)
	if conf.Auth == nil {
		conf.Auth = &gateonv1.AuthConfig{}
	}
	conf.Auth.PasetoSecret = req.PasetoSecret
	conf.Auth.Enabled = true

	if conf.Management == nil {
		conf.Management = &gateonv1.ManagementConfig{}
	}
	if req.ManagementBind != "" {
		conf.Management.Bind = req.ManagementBind
	}
	if req.ManagementPort != "" {
		conf.Management.Port = req.ManagementPort
	}

	if err := s.Globals.Update(ctx, conf); err != nil {
		return &gateonv1.SetupResponse{Success: false, Error: "failed to update config: " + err.Error()}, nil
	}

	// 3. Update Auth Manager key in-memory
	s.Auth.UpdateSymmetricKey(req.PasetoSecret)

	return &gateonv1.SetupResponse{Success: true}, nil
}

func (s *ApiService) ListUsers(_ context.Context, req *gateonv1.ListUsersRequest) (*gateonv1.ListUsersResponse, error) {
	if req == nil {
		return &gateonv1.ListUsersResponse{}, nil
	}
	if s.Auth == nil {
		return &gateonv1.ListUsersResponse{}, nil
	}
	users, totalCount, err := s.Auth.ListUsers(req.Page, req.PageSize, req.Search)
	if err != nil {
		return nil, err
	}
	return &gateonv1.ListUsersResponse{
		Users:      users,
		TotalCount: totalCount,
		Page:       req.Page,
		PageSize:   req.PageSize,
	}, nil
}

func (s *ApiService) UpdateUser(_ context.Context, req *gateonv1.UpdateUserRequest) (*gateonv1.UpdateUserResponse, error) {
	if s.Auth == nil || req == nil || req.User == nil {
		return &gateonv1.UpdateUserResponse{Success: false}, nil
	}
	if err := s.Auth.UpsertUser(req.User); err != nil {
		return &gateonv1.UpdateUserResponse{Success: false}, err
	}
	return &gateonv1.UpdateUserResponse{Success: true}, nil
}

func (s *ApiService) DeleteUser(_ context.Context, req *gateonv1.DeleteUserRequest) (*gateonv1.DeleteUserResponse, error) {
	if s.Auth == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteUserResponse{Success: false}, nil
	}
	if err := s.Auth.DeleteUser(req.Id); err != nil {
		return &gateonv1.DeleteUserResponse{Success: false}, err
	}
	return &gateonv1.DeleteUserResponse{Success: true}, nil
}

func (s *ApiService) GetDiagnostics(ctx context.Context, _ *gateonv1.GetDiagnosticsRequest) (*gateonv1.GetDiagnosticsResponse, error) {
	entrypoints := s.EntryPoints.List(ctx)
	routes := s.Routes.List(ctx)
	services := s.Services.List(ctx)
	middlewares := s.Middlewares.List(ctx)

	// Build lookup maps
	serviceMap := make(map[string]*gateonv1.Service)
	for _, svc := range services {
		serviceMap[svc.Id] = svc
	}

	middlewareMap := make(map[string]*gateonv1.Middleware)
	for _, mw := range middlewares {
		middlewareMap[mw.Id] = mw
	}

	// Group routes by entrypoint
	epToRoutes := make(map[string][]*gateonv1.Route)
	for _, rt := range routes {
		for _, epID := range rt.Entrypoints {
			epToRoutes[epID] = append(epToRoutes[epID], rt)
		}
	}

	diagEPs := make([]*gateonv1.EntryPointDiagnostic, 0, len(entrypoints))
	epNames := make(map[string]string)

	for _, ep := range entrypoints {
		epNames[ep.Id] = ep.Name
		stats := telemetry.GlobalDiagnostics.GetEPStats(ep.Id)

		d := &gateonv1.EntryPointDiagnostic{
			Id:                ep.Id,
			Name:              ep.Name,
			Address:           ep.Address,
			Type:              ep.Type.String(),
			Listening:         true, // If it's in the list and started
			TotalConnections:  stats.TotalConnections,
			ActiveConnections: stats.ActiveConnections,
			LastError:         stats.LastError,
		}

		// Enhanced Diagnostics: Route -> Middleware -> Service
		for _, rt := range epToRoutes[ep.Id] {
			rd := &gateonv1.RouteDiagnostic{
				Id:        rt.Id,
				Name:      rt.Name,
				Rule:      rt.Rule,
				ServiceId: rt.ServiceId,
				Healthy:   !rt.Disabled,
			}

			if rt.Disabled {
				rd.Error = "Route is disabled"
			}

			// Service info
			if svc, ok := serviceMap[rt.ServiceId]; ok {
				rd.ServiceName = svc.Name
				// Check service health from RouteStatsProvider if available
				if s.RouteStatsProvider != nil && !rt.Disabled {
					targetStats := s.RouteStatsProvider(rt.Id)
					rd.ServiceHealthy = true
					if len(targetStats) > 0 {
						allDown := true
						for _, ts := range targetStats {
							if ts.Alive {
								allDown = false
								break
							}
						}
						if allDown {
							rd.ServiceHealthy = false
							rd.Healthy = false
							rd.Error = "All backend targets are down"
						}
					} else {
						rd.ServiceHealthy = false
						rd.Healthy = false
						rd.Error = "No targets available for service"
					}
				}
			} else {
				rd.Healthy = false
				rd.Error = fmt.Sprintf("Service %s not found", rt.ServiceId)
			}

			// Middleware info
			for _, mwID := range rt.Middlewares {
				md := &gateonv1.MiddlewareDiagnostic{
					Id:      mwID,
					Healthy: true,
				}
				if mw, ok := middlewareMap[mwID]; ok {
					md.Name = mw.Name
					md.Type = mw.Type
				} else {
					md.Healthy = false
					md.Error = "Middleware not found"
					rd.Healthy = false
					rd.Error = fmt.Sprintf("Middleware %s not found", mwID)
				}
				rd.Middlewares = append(rd.Middlewares, md)
			}

			d.Routes = append(d.Routes, rd)
		}

		diagEPs = append(diagEPs, d)
	}

	recentErrors := telemetry.GlobalDiagnostics.GetRecentTLSErrors()
	diagErrors := make([]*gateonv1.HandshakeError, 0, len(recentErrors))
	for _, e := range recentErrors {
		name := epNames[e.EntryPointID]
		if name == "" {
			name = e.EntryPointID
		}
		diagErrors = append(diagErrors, &gateonv1.HandshakeError{
			Timestamp:      e.Timestamp.Format(time.RFC3339),
			RemoteAddr:     e.RemoteAddr,
			Error:          e.Error,
			EntrypointId:   e.EntryPointID,
			EntrypointName: name,
		})
	}

	return &gateonv1.GetDiagnosticsResponse{
		Entrypoints:     diagEPs,
		RecentTlsErrors: diagErrors,
		System: &gateonv1.SystemInfo{
			PublicIp:            getPublicIP(),
			CloudflareReachable: isCloudflareReachable(),
		},
	}, nil
}

func (s *ApiService) GetCloudflareIPs(ctx context.Context, _ *gateonv1.GetCloudflareIPsRequest) (*gateonv1.GetCloudflareIPsResponse, error) {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.cloudflare.com/client/v4/ips")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch cloudflare ips: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloudflare api returned status: %d", resp.StatusCode)
	}

	var cfResp struct {
		Result struct {
			IPv4CIDRs []string `json:"ipv4_cidrs"`
			IPv6CIDRs []string `json:"ipv6_cidrs"`
		} `json:"result"`
		Success bool `json:"success"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		return nil, fmt.Errorf("failed to decode cloudflare response: %w", err)
	}

	if !cfResp.Success {
		return nil, errors.New("cloudflare api reported failure")
	}

	return &gateonv1.GetCloudflareIPsResponse{
		Ipv4Cidrs: cfResp.Result.IPv4CIDRs,
		Ipv6Cidrs: cfResp.Result.IPv6CIDRs,
	}, nil
}

func getPublicIP() string {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()
	ip, _ := io.ReadAll(resp.Body)
	return string(ip)
}

func isCloudflareReachable() bool {
	conn, err := net.DialTimeout("tcp", "1.1.1.1:53", 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (s *ApiService) ChangePassword(_ context.Context, req *gateonv1.ChangePasswordRequest) (*gateonv1.ChangePasswordResponse, error) {
	if s.Auth == nil || req == nil || req.Id == "" || req.Password == "" {
		return &gateonv1.ChangePasswordResponse{Success: false}, nil
	}
	if err := s.Auth.ChangePassword(req.Id, req.Password); err != nil {
		return &gateonv1.ChangePasswordResponse{Success: false}, err
	}
	return &gateonv1.ChangePasswordResponse{Success: true}, nil
}
