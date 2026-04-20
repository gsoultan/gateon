package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
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

// writeJSONError writes a JSON error object and status code.
func writeJSONError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

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
		if conf.Log != nil && conf.Log.PathStatsRetentionDays > 0 {
			telemetry.ConfigureRetention(int(conf.Log.PathStatsRetentionDays))
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
			writeJSONError(w, http.StatusUnauthorized, "not authenticated")
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
		if snap, err := telemetry.CollectMetricsSnapshot(); err == nil {
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
		})
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
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
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
			writeJSONError(w, http.StatusForbidden, "test-db is only allowed during initial setup")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		var body testDBReq
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json")
			return
		}
		dsn := body.DatabaseUrl
		if dsn == "" {
			dsn = db.BuildURLFromConfig(body.DatabaseConfig)
		}
		if dsn == "" {
			writeJSONError(w, http.StatusBadRequest, "missing database configuration")
			return
		}
		conn, _, err := db.Open(dsn)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "connection failed: "+err.Error())
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
			AdminUsername  string                   `json:"admin_username"`
			AdminPassword  string                   `json:"admin_password"`
			PasetoSecret   string                   `json:"paseto_secret"`
			ManagementBind string                   `json:"management_bind"`
			ManagementPort string                   `json:"management_port"`
			DatabaseUrl    string                   `json:"database_url"`
			DatabaseConfig *gateonv1.DatabaseConfig `json:"database_config"`
		}
		var body setupBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid json"})
			return
		}

		// If DB settings are provided, validate connection and persist to globals before setup
		if body.DatabaseUrl != "" || body.DatabaseConfig != nil {
			dsn := body.DatabaseUrl
			if dsn == "" {
				dsn = db.BuildURLFromConfig(body.DatabaseConfig)
			}
			if dsn == "" {
				writeJSONError(w, http.StatusBadRequest, "invalid database configuration")
				return
			}
			conn, _, err := db.Open(dsn)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "failed to connect to database: "+err.Error())
				return
			}
			_ = conn.Close()
			// Persist selected DB into global config
			gc := svc.GetGlobals().Get(r.Context())
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
			if err := svc.GetGlobals().Update(r.Context(), gc); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "failed to persist database settings")
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
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req gateonv1.LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json")
			return
		}
		resp, err := svc.Login(r.Context(), &req)
		if err != nil {
			if errors.Is(err, auth.ErrInvalidCredentials) {
				logger.SecurityEvent("auth_failure", r, "invalid_credentials")
			}
			writeJSONError(w, http.StatusUnauthorized, err.Error())
			return
		}
		// Set HttpOnly secure cookie for session (24h) to reduce XSS exposure
		middleware.SetSessionCookie(w, resp.Token, 24*3600, r.TLS != nil)
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
			writeJSONError(w, http.StatusInternalServerError, err.Error())
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
			writeJSONError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if !auth.ValidRole(req.Role) {
			writeJSONError(w, http.StatusBadRequest, "invalid role: must be admin, operator, or viewer")
			return
		}
		resp, err := svc.UpdateUser(r.Context(), &gateonv1.UpdateUserRequest{User: &req})
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/users/password", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req gateonv1.ChangePasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if req.Id == "" || req.Password == "" {
			writeJSONError(w, http.StatusBadRequest, "id and password are required")
			return
		}

		// Allow if admin OR if changing own password
		claimsVal := r.Context().Value(middleware.UserContextKey)
		if claimsVal != nil {
			if claims, ok := claimsVal.(*auth.Claims); ok && claims != nil {
				isAdmin := auth.Allowed(claims.Role, auth.ActionWrite, auth.ResourceUsers)
				isSelf := claims.ID == req.Id
				if !isAdmin && !isSelf {
					writeJSONError(w, http.StatusForbidden, "insufficient permissions")
					return
				}
			}
		}

		resp, err := svc.ChangePassword(r.Context(), &req)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
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
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/logout", func(w http.ResponseWriter, r *http.Request) {
		middleware.ClearSessionCookie(w, r.TLS != nil)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	})
}
