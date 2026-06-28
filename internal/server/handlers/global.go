package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// decodeGlobalConfig decodes body as protobuf JSON first, then plain JSON.
func decodeGlobalConfig(body []byte, conf *gateonv1.GlobalConfig) error {
	if err := ProtojsonUnmarshalOptions().Unmarshal(body, conf); err == nil {
		return nil
	}
	if err := json.Unmarshal(body, conf); err != nil {
		return errors.New("invalid json")
	}
	return nil
}

// validateDatabase resolves a DSN from the provided URL/config and verifies a
// connection can be established. databaseURL takes precedence over cfg.
func validateDatabase(databaseURL string, cfg *gateonv1.DatabaseConfig) error {
	dsn := databaseURL
	if dsn == "" {
		dsn = db.BuildURLFromConfig(cfg)
	}
	if dsn == "" {
		return errors.New("invalid database configuration")
	}
	conn, _, err := db.Open(dsn)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	_ = conn.Close()
	return nil
}

// registerGlobalHandlers registers global configuration and utility handlers.
func registerGlobalHandlers(mux *http.ServeMux, svc GlobalAndAuthAPI, d *Deps) {
	mux.HandleFunc("GET /v1/global", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		gc := svc.GetGlobals().Get(r.Context())

		if gc.Tls != nil && len(gc.Tls.Certificates) > 0 {
			tm := svc.GetTLSManager()
			if tm != nil {
				for _, c := range gc.Tls.Certificates {
					if c.CertFile != "" && c.KeyFile != "" {
						v, err := tm.ValidateCertificateFiles(c.CertFile, c.KeyFile, c.CaFile)
						if err == nil {
							c.Validation = v
						}
					}
				}
			}
		}

		data, _ := ProtojsonOptions().Marshal(gc)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /v1/audit/logs", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		page, pageSize, search := ParsePagination(r)
		// Fall back to the legacy `limit` query param as the page size so older
		// clients keep working.
		if pageSize <= 0 {
			if lStr := r.URL.Query().Get("limit"); lStr != "" {
				if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
					pageSize = int32(l)
				}
			}
		}
		if pageSize <= 0 {
			pageSize = 100
		}
		logs, total, err := audit.GetLogsPaginated(r.Context(), int(page), int(pageSize), search)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"logs":        logs,
			"total_count": total,
			"page":        page,
			"page_size":   pageSize,
		})
	})
	mux.HandleFunc("GET /v1/audit/logs/watch", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		SetSSEHeaders(w)

		ch := audit.Subscribe()
		if ch == nil {
			http.Error(w, "Audit manager not initialized", http.StatusInternalServerError)
			return
		}
		defer audit.Unsubscribe(ch)

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		for {
			select {
			case entry, ok := <-ch:
				if !ok {
					return
				}
				data, _ := json.Marshal(entry)
				_, _ = fmt.Fprintf(w, "data: %s\n\n", string(data))
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
	handleUpdateGlobal := func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var conf gateonv1.GlobalConfig
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBodySize))
		if err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "failed to read body")
			return
		}
		if err := decodeGlobalConfig(body, &conf); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := svc.GetGlobals().Update(r.Context(), &conf); err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to update global config")
			return
		}

		// Audit Log
		claims, _ := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
		userID := "system"
		if claims != nil {
			userID = claims.Username
		}
		audit.Log(r.Context(), userID, "update", "global_config", "Updated global configuration", request.GetClientIP(r, true))

		// Apply settings that require immediate action
		if conf.Log != nil && conf.Log.PathStatsRetentionDays > 0 {
			telemetry.ConfigureRetention(int(conf.Log.PathStatsRetentionDays))
		}
		if conf.Waf != nil {
			middleware.InvalidateWAFCache()
		}
		// WAF and advanced-security middlewares are composed into each route's
		// handler at build time (router.ApplyRouteMiddlewares), so toggling them
		// only takes effect once the cached route proxies are rebuilt.
		if (conf.Waf != nil || conf.SecurityAdvanced != nil) && d.InvalidateAllProxies != nil {
			d.InvalidateAllProxies()
		}
		if conf.Geoip != nil && conf.Geoip.Enabled {
			if conf.Geoip.DbPath != "" {
				_ = telemetry.InitGeoIP(conf.Geoip.DbPath)
			}
			if conf.Geoip.XdpGeofencing && svc.GetEbpfManager() != nil {
				for _, country := range conf.Geoip.BlockedCountries {
					_ = svc.GetEbpfManager().BlockCountry(country)
				}
			}
		}

		_ = json.NewEncoder(w).Encode(struct {
			Success bool `json:"success,omitzero"`
		}{Success: true})
	}
	mux.HandleFunc("POST /v1/global", handleUpdateGlobal)
	mux.HandleFunc("PUT /v1/global", handleUpdateGlobal)
	mux.HandleFunc("PUT /v1/config", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "/v1/global"
		mux.ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /v1/me", func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
		if !ok || claims == nil {
			WriteHTTPError(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user": map[string]string{
				"id":       claims.ID,
				"username": claims.Username,
				"role":     claims.Role,
			},
		})
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		_, routesCount := d.RouteService.ListPaginated(r.Context(), 0, 0, "", nil)
		_, servicesCount := d.ServiceService.ListPaginated(r.Context(), 0, 0, "")
		_, epsCount := d.EpService.ListPaginated(r.Context(), 0, 0, "")
		_, mwsCount := d.MwService.ListPaginated(r.Context(), 0, 0, "")

		var cpuUsage, memUsage float64
		if snap, err := telemetry.CollectMetricsSnapshot(r.Context(), 50, 0); err == nil {
			cpuUsage = snap.System.CPUUsage
			memUsage = snap.System.MemoryUsage
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":               "running",
			"version":              d.Version,
			"uptime":               time.Since(d.StartTime).Seconds(),
			"memory_usage":         m.Alloc,
			"cpu_usage":            cpuUsage,
			"memory_usage_percent": memUsage,
			"routes_count":         routesCount,
			"services_count":       servicesCount,
			"entry_points_count":   epsCount,
			"middlewares_count":    mwsCount,
			"clamav_installed":     svc.GetClamAVStatus(r.Context()),
		})
	})
	mux.HandleFunc("GET /v1/status/watch", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceGlobal) {
			return
		}
		SetSSEHeaders(w)

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				_, routesCount := d.RouteService.ListPaginated(r.Context(), 0, 0, "", nil)
				_, servicesCount := d.ServiceService.ListPaginated(r.Context(), 0, 0, "")
				_, epsCount := d.EpService.ListPaginated(r.Context(), 0, 0, "")
				_, mwsCount := d.MwService.ListPaginated(r.Context(), 0, 0, "")

				var cpuUsage, memUsage float64
				if snap, err := telemetry.CollectMetricsSnapshot(r.Context(), 50, 0); err == nil {
					cpuUsage = snap.System.CPUUsage
					memUsage = snap.System.MemoryUsage
				}

				status := map[string]any{
					"status":               "running",
					"version":              d.Version,
					"uptime":               time.Since(d.StartTime).Seconds(),
					"memory_usage":         m.Alloc,
					"cpu_usage":            cpuUsage,
					"memory_usage_percent": memUsage,
					"routes_count":         routesCount,
					"services_count":       servicesCount,
					"entry_points_count":   epsCount,
					"middlewares_count":    mwsCount,
					"clamav_installed":     svc.GetClamAVStatus(r.Context()),
				}
				data, _ := json.Marshal(status)
				_, _ = fmt.Fprintf(w, "data: %s\n\n", string(data))
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
	mux.HandleFunc("POST /v1/security/clamav/install", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var req gateonv1.InstallClamavRequest
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBodySize))
		if err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "failed to read body")
			return
		}
		if err := ProtojsonUnmarshalOptions().Unmarshal(body, &req); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}

		resp, err := svc.InstallClamav(r.Context(), &req)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/security/clamav/uninstall", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp, err := svc.UninstallClamav(r.Context(), &gateonv1.UninstallClamavRequest{})
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/security/clamav/scan", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp, err := svc.RunDeepScan(r.Context(), &gateonv1.RunDeepScanRequest{})
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/waf/update", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp, err := svc.TriggerWafUpdate(r.Context(), &gateonv1.TriggerWafUpdateRequest{})
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, err := ProtojsonOptions().Marshal(resp)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to marshal response")
			return
		}
		if _, err := w.Write(data); err != nil {
			logger.L.LogError("failed to write response", "error", err)
		}
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.HandleFunc("GET /v1/setup/required", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp, err := svc.IsSetupRequired(r.Context(), &gateonv1.IsSetupRequiredRequest{})
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, err := ProtojsonOptions().Marshal(resp)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to marshal response")
			return
		}
		if _, err := w.Write(data); err != nil {
			logger.L.LogError("failed to write response", "error", err)
		}
	})
	// Test DB connection endpoint for first-run wizard
	type testDBReq struct {
		DatabaseUrl    string                   `json:"database_url"`
		DatabaseConfig *gateonv1.DatabaseConfig `json:"database_config"`
	}
	mux.HandleFunc("POST /v1/setup/test-db", func(w http.ResponseWriter, r *http.Request) {
		// Only allow test-db during setup
		setupReq, err := svc.IsSetupRequired(r.Context(), &gateonv1.IsSetupRequiredRequest{})
		if err == nil && !setupReq.Required {
			WriteHTTPError(w, http.StatusForbidden, "test-db is only allowed during initial setup")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		var body testDBReq
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "invalid json")
			return
		}
		dsn := body.DatabaseUrl
		if dsn == "" {
			dsn = db.BuildURLFromConfig(body.DatabaseConfig)
		}
		if dsn == "" {
			WriteHTTPError(w, http.StatusBadRequest, "missing database configuration")
			return
		}
		conn, _, err := db.Open(dsn)
		if err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "connection failed: "+err.Error())
			return
		}
		_ = conn.Close()
		_ = json.NewEncoder(w).Encode(struct {
			Success bool `json:"success"`
		}{Success: true})
	})
	mux.HandleFunc("POST /v1/setup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Accept extended payload including database settings for first-run wizard
		type setupBody struct {
			AdminUsername         string                   `json:"admin_username"`
			AdminPassword         string                   `json:"admin_password"`
			PasetoSecret          string                   `json:"paseto_secret"`
			ManagementBind        string                   `json:"management_bind"`
			ManagementPort        string                   `json:"management_port"`
			DatabaseUrl           string                   `json:"database_url"`
			DatabaseConfig        *gateonv1.DatabaseConfig `json:"database_config"`
			LoggingDatabaseUrl    string                   `json:"logging_database_url"`
			LoggingDatabaseConfig *gateonv1.DatabaseConfig `json:"logging_database_config"`
		}
		var body setupBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "invalid json")
			return
		}

		// If DB settings are provided, validate connections and persist to globals before setup.
		hasManagementDB := body.DatabaseUrl != "" || body.DatabaseConfig != nil
		hasLoggingDB := body.LoggingDatabaseUrl != "" || body.LoggingDatabaseConfig != nil
		if hasManagementDB || hasLoggingDB {
			gc := svc.GetGlobals().Get(r.Context())
			if hasManagementDB {
				if err := validateDatabase(body.DatabaseUrl, body.DatabaseConfig); err != nil {
					WriteHTTPError(w, http.StatusBadRequest, err.Error())
					return
				}
				if gc.Auth == nil {
					gc.Auth = &gateonv1.AuthConfig{}
				}
				if body.DatabaseUrl != "" {
					gc.Auth.DatabaseUrl = body.DatabaseUrl
					gc.Auth.DatabaseConfig = nil
					gc.Auth.SqlitePath = ""
				} else {
					gc.Auth.DatabaseConfig = body.DatabaseConfig
					gc.Auth.DatabaseUrl = ""
					gc.Auth.SqlitePath = ""
				}
			}
			if hasLoggingDB {
				if err := validateDatabase(body.LoggingDatabaseUrl, body.LoggingDatabaseConfig); err != nil {
					WriteHTTPError(w, http.StatusBadRequest, "logging database: "+err.Error())
					return
				}
				if gc.Audit == nil {
					gc.Audit = &gateonv1.AuditConfig{}
				}
				if body.LoggingDatabaseUrl != "" {
					gc.Audit.DatabaseUrl = body.LoggingDatabaseUrl
					gc.Audit.DatabaseConfig = nil
				} else {
					gc.Audit.DatabaseConfig = body.LoggingDatabaseConfig
					gc.Audit.DatabaseUrl = ""
				}
			}
			if err := svc.GetGlobals().Update(r.Context(), gc); err != nil {
				WriteHTTPError(w, http.StatusInternalServerError, "failed to persist database settings")
				return
			}
		}

		req := gateonv1.SetupRequest{
			AdminUsername:  body.AdminUsername,
			AdminPassword:  body.AdminPassword,
			PasetoSecret:   body.PasetoSecret,
			ManagementBind: body.ManagementBind,
			ManagementPort: body.ManagementPort,
		}
		resp, err := svc.Setup(r.Context(), &req)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, err := ProtojsonOptions().Marshal(resp)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to marshal response")
			return
		}
		if _, err := w.Write(data); err != nil {
			logger.L.LogError("failed to write response", "error", err)
		}
	})
	mux.HandleFunc("POST /v1/auth/2fa/setup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req gateonv1.Setup2FARequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "invalid json")
			return
		}

		// Verify permission (admin or self)
		claimsVal := r.Context().Value(middleware.UserContextKey)
		if claimsVal == nil {
			WriteHTTPError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if claims, ok := claimsVal.(*auth.Claims); ok && claims != nil {
			// 2FA setup is strictly self-service: the response contains the
			// TOTP secret, QR code, and recovery codes, which must only ever be
			// disclosed to the account owner. Even admins must not be able to
			// enable 2FA for another user, as that would hand them the second
			// factor and allow account takeover.
			if claims.ID != req.Id {
				WriteHTTPError(w, http.StatusForbidden, "2FA can only be set up for your own account")
				return
			}
		}

		resp, err := svc.Setup2FA(r.Context(), &req)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, err := ProtojsonOptions().Marshal(resp)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to marshal response")
			return
		}
		if _, err := w.Write(data); err != nil {
			logger.L.LogError("failed to write response", "error", err)
		}
	})
	mux.HandleFunc("POST /v1/auth/2fa/verify", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req gateonv1.Verify2FARequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "invalid json")
			return
		}

		// If it's for enabling (authenticated user)
		claimsVal := r.Context().Value(middleware.UserContextKey)
		var isLoginStep bool
		if claimsVal == nil {
			// Might be the second step of login, which is not yet "authenticated" in context
			isLoginStep = true
		}

		resp, err := svc.Verify2FA(r.Context(), &req)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrAccountLocked):
				logger.SecurityEvent("auth_2fa_locked", r, "account_locked")
				audit.Log(r.Context(), req.Id, "2fa_locked", "auth", "Account locked during 2FA", request.GetClientIP(r, true))
				WriteHTTPError(w, http.StatusTooManyRequests, err.Error())
			case errors.Is(err, auth.ErrInvalidTwoFactorCode):
				logger.SecurityEvent("auth_2fa_failure", r, "invalid_2fa_code")
				audit.Log(r.Context(), req.Id, "2fa_failed", "auth", "Invalid 2FA code", request.GetClientIP(r, true))
				WriteHTTPError(w, http.StatusUnauthorized, err.Error())
			default:
				WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			}
			return
		}

		if resp.Success && isLoginStep {
			// Set HttpOnly secure cookie for session (24h)
			middleware.SetSessionCookie(w, resp.Token, 24*3600, r.TLS != nil)
		}

		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	// First-time 2FA enrollment during login, used when an administrator mandated
	// 2FA for an account that has not enrolled yet. It re-verifies the password (no
	// session exists at this point), so the TOTP secret is only disclosed to
	// someone who already passed the first factor. The client then completes
	// enrollment via POST /v1/auth/2fa/verify with the user id and the TOTP code.
	mux.HandleFunc("POST /v1/auth/2fa/enroll", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if d.AuthManager == nil {
			WriteHTTPError(w, http.StatusServiceUnavailable, "auth not initialized")
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "invalid json")
			return
		}
		secret, qr, recovery, id, err := d.AuthManager.EnrollPending2FA(req.Username, req.Password)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrAccountLocked):
				WriteHTTPError(w, http.StatusTooManyRequests, err.Error())
			case errors.Is(err, auth.ErrAccountDisabled):
				WriteHTTPError(w, http.StatusForbidden, err.Error())
			case errors.Is(err, auth.ErrInvalidCredentials):
				logger.SecurityEvent("auth_2fa_enroll_failure", r, "invalid_credentials")
				WriteHTTPError(w, http.StatusUnauthorized, err.Error())
			default:
				WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			}
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":             id,
			"secret":         secret,
			"qr_code_url":    qr,
			"recovery_codes": recovery,
		})
	})
	mux.HandleFunc("POST /v1/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req gateonv1.LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "invalid json")
			return
		}
		resp, err := svc.Login(r.Context(), &req)
		if err != nil {
			if errors.Is(err, auth.ErrInvalidCredentials) {
				logger.SecurityEvent("auth_failure", r, "invalid_credentials")
				audit.Log(r.Context(), req.Username, "login_failed", "auth", "Invalid credentials", request.GetClientIP(r, true))
			}
			WriteHTTPError(w, http.StatusUnauthorized, err.Error())
			return
		}

		audit.Log(r.Context(), req.Username, "login", "auth", "User logged in", request.GetClientIP(r, true))

		if !resp.TwoFactorRequired && !resp.TwoFactorSetupRequired {
			// Set HttpOnly secure cookie for session (24h) to reduce XSS exposure
			middleware.SetSessionCookie(w, resp.Token, 24*3600, r.TLS != nil)
		}

		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /v1/users", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceUsers) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		page, pageSize, search := ParsePagination(r)
		resp, err := svc.ListUsers(r.Context(), &gateonv1.ListUsersRequest{
			Page: page, PageSize: pageSize, Search: search,
		})
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("PUT /v1/users", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceUsers) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var req gateonv1.User
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if !auth.ValidRole(req.Role) {
			WriteHTTPError(w, http.StatusBadRequest, "invalid role: must be admin, operator, or viewer")
			return
		}
		resp, err := svc.UpdateUser(r.Context(), &gateonv1.UpdateUserRequest{User: &req})
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Audit Log
		claims, _ := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
		userID := "system"
		if claims != nil {
			userID = claims.Username
		}
		audit.Log(r.Context(), userID, "update", "user", "Updated user: "+req.Username, request.GetClientIP(r, true))

		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/users/password", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req gateonv1.ChangePasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if req.Id == "" || req.Password == "" {
			WriteHTTPError(w, http.StatusBadRequest, "id and password are required")
			return
		}

		// Allow if admin OR if changing own password
		claimsVal := r.Context().Value(middleware.UserContextKey)
		if claimsVal != nil {
			if claims, ok := claimsVal.(*auth.Claims); ok && claims != nil {
				isAdmin := auth.Allowed(r.Context(), claims.Role, auth.ActionWrite, auth.ResourceUsers)
				isSelf := claims.ID == req.Id
				if !isAdmin && !isSelf {
					WriteHTTPError(w, http.StatusForbidden, "insufficient permissions")
					return
				}
			}
		}

		resp, err := svc.ChangePassword(r.Context(), &req)
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("DELETE /v1/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceUsers) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		id := r.PathValue("id")
		resp, err := svc.DeleteUser(r.Context(), &gateonv1.DeleteUserRequest{Id: id})
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Audit Log
		claims, _ := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
		userID := "system"
		if claims != nil {
			userID = claims.Username
		}
		audit.Log(r.Context(), userID, "delete", "user", "Deleted user ID: "+id, request.GetClientIP(r, true))

		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/logout", func(w http.ResponseWriter, r *http.Request) {
		// Audit Log
		claims, _ := r.Context().Value(middleware.UserContextKey).(*auth.Claims)
		if claims != nil {
			audit.Log(r.Context(), claims.Username, "logout", "auth", "User logged out", request.GetClientIP(r, true))
		}
		middleware.ClearSessionCookie(w, r.TLS != nil)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	})
}
