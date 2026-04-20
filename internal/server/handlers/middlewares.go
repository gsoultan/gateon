package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// MiddlewarePreset defines a predefined bundle of middlewares.
type MiddlewarePreset struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Middlewares []MiddlewarePresetItem `json:"middlewares"`
}

type MiddlewarePresetItem struct {
	Type   string            `json:"type"`
	Name   string            `json:"name"`
	Config map[string]string `json:"config"`
}

var middlewarePresets = []MiddlewarePreset{
	{
		ID:          "secure-api",
		Name:        "Secure API Route",
		Description: "Rate limit, in-flight limits, max body (10MB), and security headers",
		Middlewares: []MiddlewarePresetItem{
			{Type: "ratelimit", Name: "Rate Limit", Config: map[string]string{"requests_per_minute": "100", "burst": "20", "per_ip": "true", "storage": "local"}},
			{Type: "inflightreq", Name: "In-Flight Limit", Config: map[string]string{"amount": "10", "per_ip": "true"}},
			{Type: "buffering", Name: "Max Body 10MB", Config: map[string]string{"max_request_body_bytes": "10485760"}},
			{Type: "headers", Name: "Security Headers", Config: map[string]string{
				"set_response_X-Content-Type-Options": "nosniff", "set_response_X-Frame-Options": "DENY",
				"set_response_Referrer-Policy": "strict-origin-when-cross-origin",
				"sts_seconds":                  "31536000", "sts_include_subdomains": "true", "sts_preload": "true",
			}},
		},
	},
	{
		ID:          "file-upload",
		Name:        "File Upload Route",
		Description: "Large body (100MB) and moderate in-flight limit",
		Middlewares: []MiddlewarePresetItem{
			{Type: "buffering", Name: "Max Body 100MB", Config: map[string]string{"max_request_body_bytes": "104857600"}},
			{Type: "inflightreq", Name: "In-Flight Limit", Config: map[string]string{"amount": "5", "per_ip": "true"}},
		},
	},
	{
		ID:          "admin-api",
		Name:        "Admin API Route",
		Description: "Strict limits for sensitive endpoints",
		Middlewares: []MiddlewarePresetItem{
			{Type: "ratelimit", Name: "Strict Rate Limit", Config: map[string]string{"requests_per_minute": "60", "burst": "5", "per_ip": "true", "storage": "local"}},
			{Type: "inflightreq", Name: "In-Flight Limit", Config: map[string]string{"amount": "5", "per_ip": "true"}},
			{Type: "buffering", Name: "Max Body 1MB", Config: map[string]string{"max_request_body_bytes": "1048576"}},
		},
	},
	{
		ID:          "cloudflare-access",
		Name:        "Cloudflare Access (Zero Trust)",
		Description: "Forward auth to Cloudflare Access. Configure your CF Access policy and set address to your application's CF Access auth domain.",
		Middlewares: []MiddlewarePresetItem{
			{Type: "forwardauth", Name: "Cloudflare Access", Config: map[string]string{
				"address":               "https://your-app.cfaccess.com/cdn-cgi/access/get-identity",
				"auth_response_headers": "Cf-Access-Jwt-Assertion,Cf-Access-Client-Id,Cf-Access-Client-Email",
				"trust_forward_header":  "true",
				"forward_body":          "false",
			}},
		},
	},
}

func registerMiddlewareHandlers(mux *http.ServeMux, svc GlobalAndAuthAPI, d *Deps) {
	mux.HandleFunc("GET /v1/cloudflare-ips", func(w http.ResponseWriter, r *http.Request) {
		res, err := svc.GetCloudflareIPs(r.Context(), &gateonv1.GetCloudflareIPsRequest{})
		if err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, err.Error())
			return
		}
		WriteProtoResponse(w, http.StatusOK, res)
	})
	mux.HandleFunc("GET /v1/middlewares/presets", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(middlewarePresets)
	})
	mux.HandleFunc("GET /v1/middlewares", func(w http.ResponseWriter, r *http.Request) {
		page, pageSize, search := ParsePagination(r)
		mws, total := d.MwService.ListPaginated(r.Context(), page, pageSize, search)
		WriteProtoResponse(w, http.StatusOK, &gateonv1.ListMiddlewaresResponse{
			Middlewares: mws, TotalCount: total, Page: page, PageSize: pageSize,
		})
	})
	mux.HandleFunc("GET /v1/middlewares/{id}/routes", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			WriteHTTPError(w, http.StatusBadRequest, "missing middleware id")
			return
		}
		routes := d.MwService.RoutesUsingMiddleware(r.Context(), id)
		WriteJSON(w, http.StatusOK, map[string]any{"routes": routes})
	})
	mux.HandleFunc("PUT /v1/middlewares", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceMiddlewares) {
			return
		}
		var mw gateonv1.Middleware
		if err := DecodeRequestBody(r, &mw); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := d.MwService.SaveMiddleware(r.Context(), &mw); err != nil {
			// Validation/config errors are client errors
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		WriteProtoResponse(w, http.StatusOK, &mw)
	})
	mux.HandleFunc("DELETE /v1/middlewares/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceMiddlewares) {
			return
		}
		id := r.PathValue("id")
		if id == "" {
			WriteHTTPError(w, http.StatusBadRequest, "missing middleware id")
			return
		}
		if err := d.MwService.DeleteMiddleware(r.Context(), id); err != nil {
			WriteHTTPError(w, http.StatusInternalServerError, "failed to delete middleware")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
