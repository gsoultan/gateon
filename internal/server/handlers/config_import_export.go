package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gateon/gateon/internal/auth"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

type configExport struct {
	Routes      []*gateonv1.Route      `json:"routes"`
	Services    []*gateonv1.Service    `json:"services"`
	EntryPoints []*gateonv1.EntryPoint `json:"entry_points"`
	Middlewares []*gateonv1.Middleware `json:"middlewares"`
}

func registerConfigImportExport(mux *http.ServeMux, d *Deps) {
	mux.HandleFunc("GET /v1/config/export", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceConfig) {
			return
		}
		routes, _ := d.RouteService.ListPaginated(r.Context(), 0, 10000, "", nil)
		services, _ := d.ServiceService.ListPaginated(r.Context(), 0, 10000, "")
		eps, _ := d.EpService.ListPaginated(r.Context(), 0, 10000, "")
		mws, _ := d.MwService.ListPaginated(r.Context(), 0, 10000, "")

		exp := configExport{
			Routes:      routes,
			Services:    services,
			EntryPoints: eps,
			Middlewares: mws,
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=gateon-config.json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(exp)
	})

	mux.HandleFunc("POST /v1/config/import", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceConfig) {
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "failed to read body")
			return
		}
		var exp configExport
		if err := json.Unmarshal(body, &exp); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}
		errs := runConfigImport(r.Context(), d, &exp)
		writeImportResponse(w, &exp, errs)
	})

	mux.HandleFunc("POST /v1/config/validate", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "failed to read body")
			return
		}
		var exp configExport
		if err := json.Unmarshal(body, &exp); err != nil {
			writeValidateResponse(w, false, []string{}, "invalid json: "+err.Error())
			return
		}
		errs := validateConfigExport(&exp)
		if len(errs) > 0 {
			writeValidateResponse(w, false, errs, "")
			return
		}
		writeValidateResponse(w, true, nil, "")
	})
}

// runConfigImport saves services, entrypoints, middlewares, and routes; returns collected errors.
func runConfigImport(ctx context.Context, d *Deps, exp *configExport) []string {
	var errs []string
	for _, svc := range exp.Services {
		if err := d.ServiceService.SaveService(ctx, svc); err != nil {
			errs = append(errs, "service "+svc.Id+": "+err.Error())
		}
	}
	for _, ep := range exp.EntryPoints {
		if err := d.EpService.SaveEntryPoint(ctx, ep); err != nil {
			errs = append(errs, "entrypoint "+ep.Id+": "+err.Error())
		}
	}
	for _, mw := range exp.Middlewares {
		if err := d.MwService.SaveMiddleware(ctx, mw); err != nil {
			errs = append(errs, "middleware "+mw.Id+": "+err.Error())
		}
	}
	for _, rt := range exp.Routes {
		if err := d.RouteService.SaveRoute(ctx, rt); err != nil {
			errs = append(errs, "route "+rt.Id+": "+err.Error())
		}
	}
	return errs
}

// writeImportResponse writes JSON import result (success flag and optional errors).
func writeImportResponse(w http.ResponseWriter, exp *configExport, errs []string) {
	w.Header().Set("Content-Type", "application/json")
	total := len(exp.Routes) + len(exp.Services) + len(exp.EntryPoints) + len(exp.Middlewares)
	success := len(errs) < total
	if len(errs) > 0 {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": success, "errors": errs})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// validateConfigExport returns validation errors for the export payload.
func validateConfigExport(exp *configExport) []string {
	var errs []string
	for _, svc := range exp.Services {
		if svc.Id == "" || svc.Name == "" {
			errs = append(errs, "service: missing id or name")
		}
		if len(svc.WeightedTargets) == 0 {
			errs = append(errs, "service "+svc.Id+": no targets")
		}
	}
	for _, rt := range exp.Routes {
		if rt.Id == "" {
			errs = append(errs, "route: missing id")
		}
		if rt.Rule == "" {
			errs = append(errs, "route "+rt.Id+": missing rule")
		}
		if rt.ServiceId == "" {
			errs = append(errs, "route "+rt.Id+": missing service_id")
		}
	}
	return errs
}

// writeValidateResponse writes JSON validation result.
func writeValidateResponse(w http.ResponseWriter, valid bool, errs []string, errorMsg string) {
	w.Header().Set("Content-Type", "application/json")
	if errorMsg != "" {
		_ = json.NewEncoder(w).Encode(map[string]any{"valid": false, "error": errorMsg})
		return
	}
	if len(errs) > 0 {
		_ = json.NewEncoder(w).Encode(map[string]any{"valid": false, "errors": errs})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"valid": true})
}
