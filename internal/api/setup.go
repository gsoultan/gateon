package api

import (
	"context"
	"slices"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/db"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

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
	admin := &gateonv1.User{
		Username: req.AdminUsername,
		Password: req.AdminPassword,
		Role:     auth.RoleAdmin,
	}
	if existing, _, _ := s.Auth.ListUsers(0, 1000, admin.Username); len(existing) > 0 {
		if i := slices.IndexFunc(existing, func(u *gateonv1.User) bool { return u.Username == admin.Username }); i >= 0 {
			admin.Id = existing[i].Id
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
