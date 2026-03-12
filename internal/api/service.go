package api

import (
	"context"
	"errors"
	"runtime"
	"time"

	"github.com/gateon/gateon/internal/auth"
	"github.com/gateon/gateon/internal/config"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

type ApiService struct {
	gateonv1.UnimplementedApiServiceServer
	Version     string
	Routes      config.RouteStore
	Services    config.ServiceStore
	Globals     config.GlobalConfigStore
	EntryPoints config.EntryPointStore
	Middlewares config.MiddlewareStore
	TLSOptions  config.TLSOptionStore
	Auth        auth.Service
}

// ApiServiceConfig holds dependencies for ApiService (Factory pattern).
type ApiServiceConfig struct {
	Version     string
	Routes      config.RouteStore
	Services    config.ServiceStore
	Globals     config.GlobalConfigStore
	EntryPoints config.EntryPointStore
	Middlewares config.MiddlewareStore
	TLSOptions  config.TLSOptionStore
	Auth        auth.Service
}

// NewApiService creates an ApiService from config (Factory pattern).
func NewApiService(cfg ApiServiceConfig) *ApiService {
	return &ApiService{
		Version:     cfg.Version,
		Routes:      cfg.Routes,
		Services:    cfg.Services,
		Globals:     cfg.Globals,
		EntryPoints: cfg.EntryPoints,
		Middlewares: cfg.Middlewares,
		TLSOptions:  cfg.TLSOptions,
		Auth:        cfg.Auth,
	}
}

func (s *ApiService) ListEntryPoints(_ context.Context, _ *gateonv1.ListEntryPointsRequest) (*gateonv1.ListEntryPointsResponse, error) {
	if s.EntryPoints == nil {
		return &gateonv1.ListEntryPointsResponse{EntryPoints: nil}, nil
	}
	return &gateonv1.ListEntryPointsResponse{EntryPoints: s.EntryPoints.List()}, nil
}

func (s *ApiService) UpdateEntryPoint(_ context.Context, req *gateonv1.UpdateEntryPointRequest) (*gateonv1.UpdateEntryPointResponse, error) {
	if s.EntryPoints == nil || req == nil || req.EntryPoint == nil {
		return &gateonv1.UpdateEntryPointResponse{Success: false}, nil
	}
	if err := s.EntryPoints.Update(req.EntryPoint); err != nil {
		return &gateonv1.UpdateEntryPointResponse{Success: false}, err
	}
	return &gateonv1.UpdateEntryPointResponse{Success: true}, nil
}

func (s *ApiService) DeleteEntryPoint(_ context.Context, req *gateonv1.DeleteEntryPointRequest) (*gateonv1.DeleteEntryPointResponse, error) {
	if s.EntryPoints == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteEntryPointResponse{Success: false}, nil
	}
	if err := s.EntryPoints.Delete(req.Id); err != nil {
		return &gateonv1.DeleteEntryPointResponse{Success: false}, err
	}
	return &gateonv1.DeleteEntryPointResponse{Success: true}, nil
}

var startTime = time.Now()

func (s *ApiService) GetStatus(_ context.Context, _ *gateonv1.GetStatusRequest) (*gateonv1.GetStatusResponse, error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	routesCount := 0
	if s.Routes != nil {
		routesCount = len(s.Routes.List())
	}
	servicesCount := 0
	if s.Services != nil {
		servicesCount = len(s.Services.List())
	}

	return &gateonv1.GetStatusResponse{
		Status:        "running",
		Version:       s.Version,
		Uptime:        int64(time.Since(startTime).Seconds()),
		MemoryUsage:   int64(m.Alloc),
		RoutesCount:   int32(routesCount),
		ServicesCount: int32(servicesCount),
	}, nil
}

func (s *ApiService) ListRoutes(_ context.Context, _ *gateonv1.ListRoutesRequest) (*gateonv1.ListRoutesResponse, error) {
	if s.Routes == nil {
		return &gateonv1.ListRoutesResponse{Routes: nil}, nil
	}
	return &gateonv1.ListRoutesResponse{Routes: s.Routes.List()}, nil
}

func (s *ApiService) UpdateRoute(_ context.Context, req *gateonv1.UpdateRouteRequest) (*gateonv1.UpdateRouteResponse, error) {
	if s.Routes == nil || req == nil || req.Route == nil {
		return &gateonv1.UpdateRouteResponse{Success: false}, nil
	}
	if err := s.Routes.Update(req.Route); err != nil {
		return &gateonv1.UpdateRouteResponse{Success: false}, err
	}
	return &gateonv1.UpdateRouteResponse{Success: true}, nil
}

func (s *ApiService) DeleteRoute(_ context.Context, req *gateonv1.DeleteRouteRequest) (*gateonv1.DeleteRouteResponse, error) {
	if s.Routes == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteRouteResponse{Success: false}, nil
	}
	if err := s.Routes.Delete(req.Id); err != nil {
		return &gateonv1.DeleteRouteResponse{Success: false}, err
	}
	return &gateonv1.DeleteRouteResponse{Success: true}, nil
}

func (s *ApiService) ListServices(_ context.Context, _ *gateonv1.ListServicesRequest) (*gateonv1.ListServicesResponse, error) {
	if s.Services == nil {
		return &gateonv1.ListServicesResponse{Services: nil}, nil
	}
	return &gateonv1.ListServicesResponse{Services: s.Services.List()}, nil
}

func (s *ApiService) UpdateService(_ context.Context, req *gateonv1.UpdateServiceRequest) (*gateonv1.UpdateServiceResponse, error) {
	if s.Services == nil || req == nil || req.Service == nil {
		return &gateonv1.UpdateServiceResponse{Success: false}, nil
	}
	if err := s.Services.Update(req.Service); err != nil {
		return &gateonv1.UpdateServiceResponse{Success: false}, err
	}
	return &gateonv1.UpdateServiceResponse{Success: true}, nil
}

func (s *ApiService) DeleteService(_ context.Context, req *gateonv1.DeleteServiceRequest) (*gateonv1.DeleteServiceResponse, error) {
	if s.Services == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteServiceResponse{Success: false}, nil
	}
	if err := s.Services.Delete(req.Id); err != nil {
		return &gateonv1.DeleteServiceResponse{Success: false}, err
	}
	return &gateonv1.DeleteServiceResponse{Success: true}, nil
}

func (s *ApiService) GetGlobalConfig(_ context.Context, _ *gateonv1.GetGlobalConfigRequest) (*gateonv1.GlobalConfig, error) {
	if s.Globals == nil {
		return &gateonv1.GlobalConfig{}, nil
	}
	return s.Globals.Get(), nil
}

func (s *ApiService) UpdateGlobalConfig(_ context.Context, req *gateonv1.UpdateGlobalConfigRequest) (*gateonv1.UpdateGlobalConfigResponse, error) {
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

	if err := s.Globals.Update(req.Config); err != nil {
		return &gateonv1.UpdateGlobalConfigResponse{Success: false}, err
	}
	return &gateonv1.UpdateGlobalConfigResponse{Success: true}, nil
}

func (s *ApiService) ListMiddlewares(_ context.Context, _ *gateonv1.ListMiddlewaresRequest) (*gateonv1.ListMiddlewaresResponse, error) {
	if s.Middlewares == nil {
		return &gateonv1.ListMiddlewaresResponse{Middlewares: nil}, nil
	}
	return &gateonv1.ListMiddlewaresResponse{Middlewares: s.Middlewares.List()}, nil
}

func (s *ApiService) UpdateMiddleware(_ context.Context, req *gateonv1.UpdateMiddlewareRequest) (*gateonv1.UpdateMiddlewareResponse, error) {
	if s.Middlewares == nil || req == nil || req.Middleware == nil {
		return &gateonv1.UpdateMiddlewareResponse{Success: false}, nil
	}
	if err := s.Middlewares.Update(req.Middleware); err != nil {
		return &gateonv1.UpdateMiddlewareResponse{Success: false}, err
	}
	return &gateonv1.UpdateMiddlewareResponse{Success: true}, nil
}

func (s *ApiService) DeleteMiddleware(_ context.Context, req *gateonv1.DeleteMiddlewareRequest) (*gateonv1.DeleteMiddlewareResponse, error) {
	if s.Middlewares == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteMiddlewareResponse{Success: false}, nil
	}
	if err := s.Middlewares.Delete(req.Id); err != nil {
		return &gateonv1.DeleteMiddlewareResponse{Success: false}, err
	}
	return &gateonv1.DeleteMiddlewareResponse{Success: true}, nil
}

func (s *ApiService) ListTLSOptions(_ context.Context, _ *gateonv1.ListTLSOptionsRequest) (*gateonv1.ListTLSOptionsResponse, error) {
	if s.TLSOptions == nil {
		return &gateonv1.ListTLSOptionsResponse{TlsOptions: nil}, nil
	}
	return &gateonv1.ListTLSOptionsResponse{TlsOptions: s.TLSOptions.List()}, nil
}

func (s *ApiService) UpdateTLSOption(_ context.Context, req *gateonv1.UpdateTLSOptionRequest) (*gateonv1.UpdateTLSOptionResponse, error) {
	if s.TLSOptions == nil || req == nil || req.TlsOption == nil {
		return &gateonv1.UpdateTLSOptionResponse{Success: false}, nil
	}
	if err := s.TLSOptions.Update(req.TlsOption); err != nil {
		return &gateonv1.UpdateTLSOptionResponse{Success: false}, err
	}
	return &gateonv1.UpdateTLSOptionResponse{Success: true}, nil
}

func (s *ApiService) DeleteTLSOption(_ context.Context, req *gateonv1.DeleteTLSOptionRequest) (*gateonv1.DeleteTLSOptionResponse, error) {
	if s.TLSOptions == nil || req == nil || req.Id == "" {
		return &gateonv1.DeleteTLSOptionResponse{Success: false}, nil
	}
	if err := s.TLSOptions.Delete(req.Id); err != nil {
		return &gateonv1.DeleteTLSOptionResponse{Success: false}, err
	}
	return &gateonv1.DeleteTLSOptionResponse{Success: true}, nil
}

func (s *ApiService) Login(_ context.Context, req *gateonv1.LoginRequest) (*gateonv1.LoginResponse, error) {
	if s.Auth == nil {
		return nil, nil
	}
	token, user, err := s.Auth.Authenticate(req.Username, req.Password)
	if err != nil {
		return nil, err
	}
	return &gateonv1.LoginResponse{Token: token, User: user}, nil
}

func (s *ApiService) IsSetupRequired(_ context.Context, _ *gateonv1.IsSetupRequiredRequest) (*gateonv1.IsSetupRequiredResponse, error) {
	if s.Auth == nil {
		return &gateonv1.IsSetupRequiredResponse{Required: true}, nil
	}

	// Setup is required if:
	// 1. No users exist in the database.
	// 2. OR Paseto Secret is still the default one.

	setupDone := s.Auth.IsSetupDone()

	pasetoSecret := ""
	if s.Globals != nil {
		conf := s.Globals.Get()
		if conf != nil && conf.Auth != nil {
			pasetoSecret = conf.Auth.PasetoSecret
		}
	}

	// Default secret from global.json
	const defaultSecret = "YELLOW SUBMARINE, BLACK WIZARDRY"

	required := !setupDone || pasetoSecret == defaultSecret || pasetoSecret == ""

	return &gateonv1.IsSetupRequiredResponse{Required: required}, nil
}

func (s *ApiService) Setup(ctx context.Context, req *gateonv1.SetupRequest) (*gateonv1.SetupResponse, error) {
	if s.Auth == nil {
		// Initialize Auth Manager if it doesn't exist
		sqlitePath := "gateon.db"
		if s.Globals != nil {
			conf := s.Globals.Get()
			if conf.Auth != nil && conf.Auth.SqlitePath != "" {
				sqlitePath = conf.Auth.SqlitePath
			}
		}

		var err error
		s.Auth, err = auth.NewManager(sqlitePath, req.PasetoSecret)
		if err != nil {
			return &gateonv1.SetupResponse{Success: false, Error: "failed to initialize auth manager: " + err.Error()}, nil
		}
	}

	// 1. Create/Update Admin User
	admin := &gateonv1.User{
		Username: req.AdminUsername,
		Password: req.AdminPassword,
		Role:     auth.RoleAdmin,
	}
	if err := s.Auth.UpsertUser(admin); err != nil {
		return &gateonv1.SetupResponse{Success: false, Error: "failed to create admin: " + err.Error()}, nil
	}

	// 2. Update Global Config (Paseto Secret)
	conf := s.Globals.Get()
	if conf.Auth == nil {
		conf.Auth = &gateonv1.AuthConfig{}
	}
	conf.Auth.PasetoSecret = req.PasetoSecret
	conf.Auth.Enabled = true

	if err := s.Globals.Update(conf); err != nil {
		return &gateonv1.SetupResponse{Success: false, Error: "failed to update config: " + err.Error()}, nil
	}

	// 3. Update Auth Manager key in-memory
	s.Auth.UpdateSymmetricKey(req.PasetoSecret)

	return &gateonv1.SetupResponse{Success: true}, nil
}

func (s *ApiService) ListUsers(_ context.Context, req *gateonv1.ListUsersRequest) (*gateonv1.ListUsersResponse, error) {
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
	if s.Auth == nil || req.User == nil {
		return &gateonv1.UpdateUserResponse{Success: false}, nil
	}
	if err := s.Auth.UpsertUser(req.User); err != nil {
		return &gateonv1.UpdateUserResponse{Success: false}, err
	}
	return &gateonv1.UpdateUserResponse{Success: true}, nil
}

func (s *ApiService) DeleteUser(_ context.Context, req *gateonv1.DeleteUserRequest) (*gateonv1.DeleteUserResponse, error) {
	if s.Auth == nil || req.Id == "" {
		return &gateonv1.DeleteUserResponse{Success: false}, nil
	}
	if err := s.Auth.DeleteUser(req.Id); err != nil {
		return &gateonv1.DeleteUserResponse{Success: false}, err
	}
	return &gateonv1.DeleteUserResponse{Success: true}, nil
}
