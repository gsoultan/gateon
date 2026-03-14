package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"
	"time"

	"github.com/gateon/gateon/internal/api"
	"github.com/gateon/gateon/internal/auth"
	"github.com/gateon/gateon/internal/logger"
	"github.com/gateon/gateon/internal/middleware"
	"github.com/gateon/gateon/internal/telemetry"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
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

func registerGlobalHandlers(mux *http.ServeMux, apiService *api.ApiService, d *Deps) {
	mux.HandleFunc("GET /v1/global", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		gc := apiService.Globals.Get(r.Context())
		data, _ := ProtojsonOptions().Marshal(gc)
		_, _ = w.Write(data)
	})
	handleUpdateGlobal := func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceGlobal) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var conf gateonv1.GlobalConfig
		body, err := io.ReadAll(r.Body)
		if err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "failed to read body")
			return
		}
		if err := decodeGlobalConfig(body, &conf); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := apiService.Globals.Update(r.Context(), &conf); err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to update global config")
			return
		}
		if conf.Log != nil && conf.Log.PathStatsRetentionDays > 0 {
			telemetry.ConfigureRetention(int(conf.Log.PathStatsRetentionDays))
		}
		_ = json.NewEncoder(w).Encode(struct{ Success bool `json:"success,omitzero"` }{Success: true})
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
		w.Header().Set("Content-Type", "application/json")
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		_, routesCount := d.RouteService.ListPaginated(r.Context(), 0, 0, "", nil)
		_, servicesCount := d.ServiceService.ListPaginated(r.Context(), 0, 0, "")
		_, epsCount := d.EpService.ListPaginated(r.Context(), 0, 0, "")
		_, mwsCount := d.MwService.ListPaginated(r.Context(), 0, 0, "")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":             "running",
			"version":            d.Version,
			"uptime":             time.Since(d.StartTime).Seconds(),
			"memory_usage":       m.Alloc,
			"routes_count":       routesCount,
			"services_count":     servicesCount,
			"entry_points_count": epsCount,
			"middlewares_count":  mwsCount,
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
		resp, err := apiService.IsSetupRequired(r.Context(), &gateonv1.IsSetupRequiredRequest{})
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		data, _ := ProtojsonOptions().Marshal(resp)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("POST /v1/setup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req gateonv1.SetupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid json"})
			return
		}
		resp, err := apiService.Setup(r.Context(), &req)
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
		resp, err := apiService.Login(r.Context(), &req)
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
		resp, err := apiService.ListUsers(r.Context(), &gateonv1.ListUsersRequest{
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
		resp, err := apiService.UpdateUser(r.Context(), &gateonv1.UpdateUserRequest{User: &req})
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
		resp, err := apiService.DeleteUser(r.Context(), &gateonv1.DeleteUserRequest{Id: id})
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
