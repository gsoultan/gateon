// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/auth/passpolicy"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
)

func (s *ApiService) IsSetupRequired(ctx context.Context, _ *gateonv1.IsSetupRequiredRequest) (*gateonv1.IsSetupRequiredResponse, error) {
	// First run: no global.json file — setup required
	if s.Globals != nil && !s.Globals.ConfigFileExists() {
		return &gateonv1.IsSetupRequiredResponse{Required: true}, nil
	}
	if !auth.Available(s.Auth) {
		return &gateonv1.IsSetupRequiredResponse{Required: true}, nil
	}

	// Setup is required only while no administrator exists.
	//
	// An empty PASETO secret used to count as well ("still the default one").
	// It never described a real first run: the bootstrap generates a random key
	// whenever the stored one is empty, so the only way a running gateway
	// reached that state was a global-config write that left the field blank.
	// Treating that as "setup required" reopened Setup -- public, served before
	// authentication -- on a configured gateway, and Setup reuses the id of an
	// existing administrator with the requested username and overwrites their
	// password. That turned a global-config write into an administrator account.
	return &gateonv1.IsSetupRequiredResponse{Required: !s.Auth.IsSetupDone()}, nil
}

func (s *ApiService) Setup(ctx context.Context, req *gateonv1.SetupRequest) (*gateonv1.SetupResponse, error) {
	if req == nil {
		return &gateonv1.SetupResponse{Success: false, Error: "request is required"}, nil
	}
	// Paseto symmetric key MUST be exactly 32 bytes, unless the configuration
	// names the key and the request's is not used.
	if len(req.PasetoSecret) != 32 && s.setupSessionKey(ctx, "") == "" {
		return &gateonv1.SetupResponse{Success: false, Error: "paseto secret must be exactly 32 characters"}, nil
	}
	// Check if setup is already done
	// Fail closed on an unknown setup state. This guard is what stops Setup
	// being re-run against a configured gateway, and re-running it creates an
	// administrator -- so "I could not tell" has to deny. The old form let an
	// error through to the account-creation path below.
	setupReq, err := s.IsSetupRequired(ctx, &gateonv1.IsSetupRequiredRequest{})
	if err != nil || !setupReq.Required {
		return &gateonv1.SetupResponse{Success: false, Error: "setup already completed"}, nil
	}
	// The token, before anything here acts on the request: a database probe,
	// an account, a config write. Setup runs before any account exists, and
	// without this whoever reached a fresh gateway first could do all of that.
	// See ADR 0021.
	if !s.SetupToken.Matches(req.GetSetupToken()) {
		return &gateonv1.SetupResponse{Success: false, Error: auth.ErrSetupTokenRequired.Error()}, nil
	}
	// Before anything is written: a refused password must not leave databases
	// chosen or an auth manager installed behind it (ADR 0050). UpsertUser
	// checks again; this is so nothing has happened when it would refuse.
	if err := passpolicy.Check(req.AdminPassword, req.AdminUsername); err != nil {
		return &gateonv1.SetupResponse{Success: false, Error: err.Error()}, nil
	}
	// After the guard, never before it: this writes the auth and audit
	// databases, and on a configured gateway that would let an unauthenticated
	// caller point both at a server it controls.
	if err := applySetupDatabases(ctx, s.Globals, req); err != nil {
		return &gateonv1.SetupResponse{Success: false, Error: err.Error()}, nil
	}

	// Setup is all or nothing (review finding M13). It used to create the
	// administrator and install the auth service, then fail to write the
	// config -- a read-only or missing config directory -- and answer failure
	// with both still in place. Where global.json already existed, the
	// administrator alone closed setup for good, over a config that had
	// neither the session key nor auth.enabled. A failure now undoes what
	// this call did, so setup stays open and a retry starts clean.
	prevAuth, installed, key := s.Auth, false, s.setupSessionKey(ctx, req.PasetoSecret)
	if !auth.Available(s.Auth) {
		if err := s.installAuthManager(ctx, key); err != nil {
			return &gateonv1.SetupResponse{Success: false, Error: err.Error()}, nil
		}
		installed = true
	}
	createdID, err := s.upsertSetupAdmin(req)
	if err != nil {
		s.undoSetup(prevAuth, installed, "")
		return &gateonv1.SetupResponse{Success: false, Error: "failed to create admin: " + err.Error()}, nil
	}
	if err := s.saveSetupConfig(ctx, req, key); err != nil {
		s.undoSetup(prevAuth, installed, createdID)
		return &gateonv1.SetupResponse{Success: false, Error: "failed to update config: " + err.Error()}, nil
	}

	// 3. Put the saved key in force now. The administrator and the config are
	// already written, so a failure is reported, not returned: the next start
	// reads the saved key.
	if err := s.Auth.UpdateSymmetricKey(key); err != nil {
		logger.L.LogError("setup saved the session key but could not put it in force; restart the gateway",
			"error", err)
	}

	s.logAudit(ctx, "setup", "system", "System initial setup completed")
	// Nothing is left for the token to open, and its file should not outlive it.
	s.SetupToken.Retire()

	return &gateonv1.SetupResponse{Success: true}, nil
}

// upsertSetupAdmin creates the administrator Setup asks for, or takes over the
// account of that name, and returns the id when this call created it.
func (s *ApiService) upsertSetupAdmin(req *gateonv1.SetupRequest) (string, error) {
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
	existed := admin.Id != ""
	if err := s.Auth.UpsertUser(admin); err != nil {
		return "", err
	}
	if existed {
		return "", nil
	}
	return admin.Id, nil
}

// setupSessionKey is the session key Setup puts in force: the one the
// configuration names by reference when it names one -- GATEON_SESSION_KEY,
// which every replica of one gateway and every start on a fresh volume share
// (ADR 0056) -- and otherwise the one the wizard generated.
//
// Setup used to store the wizard's key over the reference. The replica that ran
// setup then signed with a key no other replica had; and with no persistent
// volume, the second factors enrolled under it were unreadable after the next
// restart, which brought the environment's key back.
func (s *ApiService) setupSessionKey(ctx context.Context, requested string) string {
	if s.Globals == nil {
		return requested
	}
	live := s.Globals.Get(ctx)
	view := config.WithSecretReferences(s.Globals, live)
	if key := live.GetAuth().GetPasetoSecret(); key != "" && config.IsSecretReference(view.GetAuth().GetPasetoSecret()) {
		return key
	}
	return requested
}

// saveSetupConfig writes the session key, auth.enabled and the management
// settings Setup chose to the global config.
func (s *ApiService) saveSetupConfig(ctx context.Context, req *gateonv1.SetupRequest, key string) error {
	conf, ok := proto.Clone(s.Globals.Get(ctx)).(*gateonv1.GlobalConfig)
	if !ok || conf == nil {
		conf = &gateonv1.GlobalConfig{}
	}
	if conf.Auth == nil {
		conf.Auth = &gateonv1.AuthConfig{}
	}
	conf.Auth.PasetoSecret = key
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
	recordFromTheStart(conf)
	if err := s.Globals.Update(ctx, conf); err != nil {
		return err
	}
	// The saved audit settings take effect now, so Setup's own entry below is
	// the first one recorded and signed.
	audit.UpdateConfig(conf.Audit)
	return nil
}

// undoSetup takes back what a failed Setup did: the administrator it created
// and the auth service it installed, so the gateway is as it was before the
// call -- setup still open, the token still valid.
func (s *ApiService) undoSetup(prev auth.Service, installed bool, createdID string) {
	if createdID != "" {
		if err := s.Auth.DeleteUser(createdID); err != nil {
			logger.L.LogError("setup failed and the administrator it created could not be removed", "error", err)
		}
	}
	if !installed {
		return
	}
	installedSvc := s.Auth
	if h, ok := s.Auth.(*auth.Holder); ok && h != nil {
		installedSvc = h.Get()
		h.Set(nil)
	} else {
		s.Auth = prev
	}
	if c, ok := installedSvc.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}

// recordFromTheStart turns the audit log on, signed, for an install being set
// up (ADR 0050). It was off by default, so a default install recorded nothing
// -- sign-ins, user changes, configuration changes -- and the chain its
// entries would have formed was never there to verify. Setup is the one moment
// that is unambiguously a new install: a stored "enabled": false is not
// written to global.json (it is the zero value), so an existing install that
// chose to switch audit off cannot be told from one that never chose, and is
// left as it is. An administrator can switch it off afterwards; that change is
// itself recorded.
func recordFromTheStart(conf *gateonv1.GlobalConfig) {
	if conf.Audit == nil {
		conf.Audit = &gateonv1.AuditConfig{}
	}
	conf.Audit.Enabled = true
	conf.Audit.SignEntries = true
	if conf.Audit.SignatureKey == "" {
		conf.Audit.SignatureKey = audit.GenerateSignatureKey()
	}
}

// errPersistSetupDatabases is what a caller sees when the chosen databases
// opened but could not be saved; the store's own error names file paths.
var errPersistSetupDatabases = errors.New("failed to persist database settings")

// applySetupDatabases proves the databases the wizard chose can be opened and
// writes them to the global config. It runs before installAuthManager, which
// reads the auth database from there, so the administrator is created in the
// database the operator chose rather than in the default gateon.db.
//
// Both are probed before either is written: a management database that saved
// and a logging one that then failed would leave setup half applied.
//
// This used to live only in the REST handler for POST /v1/setup. The dashboard
// calls Setup over Connect, which never read database_url or database_config,
// so the wizard's database step was accepted and discarded, and every install
// ran on gateon.db whatever the operator picked.
func applySetupDatabases(ctx context.Context, globals config.GlobalConfigStore, req *gateonv1.SetupRequest) error {
	mgmt, logs, err := probeSetupDatabases(req)
	if err != nil {
		return err
	}
	if !mgmt && !logs {
		return nil
	}
	// A copy: the registry hands out its stored pointer, and Update only
	// restores the previous config if the pointer it held was left alone.
	conf, ok := proto.Clone(globals.Get(ctx)).(*gateonv1.GlobalConfig)
	if !ok || conf == nil {
		return errPersistSetupDatabases
	}
	if mgmt {
		if conf.Auth == nil {
			conf.Auth = &gateonv1.AuthConfig{}
		}
		conf.Auth.SqlitePath = ""
		conf.Auth.DatabaseUrl, conf.Auth.DatabaseConfig = chosenDatabase(req.GetDatabaseUrl(), req.GetDatabaseConfig())
	}
	if logs {
		if conf.Audit == nil {
			conf.Audit = &gateonv1.AuditConfig{}
		}
		conf.Audit.DatabaseUrl, conf.Audit.DatabaseConfig = chosenDatabase(req.GetLoggingDatabaseUrl(), req.GetLoggingDatabaseConfig())
	}
	if err := globals.Update(ctx, conf); err != nil {
		return errPersistSetupDatabases
	}
	return nil
}

// probeSetupDatabases reports which of its two databases req names, having
// proved that each one it names can be opened.
func probeSetupDatabases(req *gateonv1.SetupRequest) (mgmt, logs bool, err error) {
	mgmt = req.GetDatabaseUrl() != "" || req.GetDatabaseConfig() != nil
	logs = req.GetLoggingDatabaseUrl() != "" || req.GetLoggingDatabaseConfig() != nil
	if mgmt {
		if err := db.Probe(req.GetDatabaseUrl(), req.GetDatabaseConfig(), config.DataDir()); err != nil {
			return false, false, err
		}
	}
	if logs {
		if err := db.Probe(req.GetLoggingDatabaseUrl(), req.GetLoggingDatabaseConfig(), config.DataDir()); err != nil {
			return false, false, fmt.Errorf("logging database: %w", err)
		}
	}
	return mgmt, logs, nil
}

// chosenDatabase keeps exactly one of the two forms. A SetupRequest's url
// overrides its config, but db.AuthDatabaseURL and db.AuditDatabaseURL read the
// config first, so storing both would open the one the operator did not pick.
func chosenDatabase(databaseURL string, cfg *gateonv1.DatabaseConfig) (string, *gateonv1.DatabaseConfig) {
	if databaseURL != "" {
		return databaseURL, nil
	}
	return "", cfg
}

// installAuthManager builds the auth manager on first run and publishes it so
// the components that enforce authentication pick it up without a restart.
//
// Extracted from Setup because the nesting there had grown past the point where
// the interesting line — the Holder swap — was visible at a glance.
func (s *ApiService) installAuthManager(ctx context.Context, pasetoSecret string) error {
	databaseURL := db.AuthDatabaseURL(nil)
	if s.Globals != nil {
		if conf := s.Globals.Get(ctx); conf != nil && conf.Auth != nil {
			databaseURL = db.AuthDatabaseURL(conf.Auth)
		}
	}

	mgr, err := auth.NewManager(databaseURL, pasetoSecret, logger.Default())
	if err != nil {
		return fmt.Errorf("failed to initialize auth manager: %w", err)
	}

	// Publish through the shared Holder when there is one. Assigning s.Auth
	// directly would only fix this one struct: the HTTP base handler, the REST
	// handler deps and the diagnostics log gate all hold the same Holder, and
	// they are what actually enforce authentication. Swapping it in place is
	// what makes them start enforcing without a restart.
	if h, ok := s.Auth.(*auth.Holder); ok && h != nil {
		h.Set(mgr)
		return nil
	}
	s.Auth = mgr
	return nil
}
