// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// MaxConfigImportBodySize limits config import/validate request body to prevent large-body DoS.
const MaxConfigImportBodySize = 5 * 1024 * 1024 // 5MB

type configExport struct {
	Routes      []*gateonv1.Route      `json:"routes"`
	Services    []*gateonv1.Service    `json:"services"`
	EntryPoints []*gateonv1.EntryPoint `json:"entry_points"`
	Middlewares []*gateonv1.Middleware `json:"middlewares"`
}

type configDiff struct {
	Created configExport `json:"created"`
	Updated configExport `json:"updated"`
}

func calculateConfigDiff(ctx context.Context, d *Deps, exp *configExport) configDiff {
	var diff configDiff
	for _, rt := range exp.Routes {
		if _, ok := d.RouteService.GetRoute(ctx, rt.Id); ok {
			diff.Updated.Routes = append(diff.Updated.Routes, rt)
		} else {
			diff.Created.Routes = append(diff.Created.Routes, rt)
		}
	}
	for _, svc := range exp.Services {
		if _, ok := d.ServiceService.GetService(ctx, svc.Id); ok {
			diff.Updated.Services = append(diff.Updated.Services, svc)
		} else {
			diff.Created.Services = append(diff.Created.Services, svc)
		}
	}
	for _, ep := range exp.EntryPoints {
		if _, ok := d.EpService.GetEntryPoint(ctx, ep.Id); ok {
			diff.Updated.EntryPoints = append(diff.Updated.EntryPoints, ep)
		} else {
			diff.Created.EntryPoints = append(diff.Created.EntryPoints, ep)
		}
	}
	for _, mw := range exp.Middlewares {
		if _, ok := d.MwService.GetMiddleware(ctx, mw.Id); ok {
			diff.Updated.Middlewares = append(diff.Updated.Middlewares, mw)
		} else {
			diff.Created.Middlewares = append(diff.Created.Middlewares, mw)
		}
	}
	return diff
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
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxConfigImportBodySize+1))
		if err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "failed to read body")
			return
		}
		if len(body) > MaxConfigImportBodySize {
			WriteHTTPError(w, http.StatusRequestEntityTooLarge, "config import body exceeds 5MB limit")
			return
		}
		var exp configExport
		if err := json.Unmarshal(body, &exp); err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}

		dryRun, err := importPreviewRequested(r.URL.Query())
		if err != nil {
			WriteHTTPError(w, http.StatusBadRequest, err.Error())
			return
		}
		if dryRun {
			diff := calculateConfigDiff(r.Context(), d, &exp)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "dry_run": true, "diff": diff})
			return
		}

		errs := runConfigImport(r.Context(), d, &exp)
		writeImportResponse(w, &exp, errs)
	})

	mux.HandleFunc("POST /v1/config/validate", func(w http.ResponseWriter, r *http.Request) {
		// Validate is the preflight for import, so it carries import's
		// permission rather than export's: a caller who cannot apply a config
		// has no reason to have the gateway parse 5MB of one.
		if !RequirePermission(w, r, auth.ActionWrite, auth.ResourceConfig) {
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxConfigImportBodySize+1))
		if err != nil {
			WriteHTTPError(w, http.StatusBadRequest, "failed to read body")
			return
		}
		if len(body) > MaxConfigImportBodySize {
			writeValidateResponse(w, false, []string{}, "config validate body exceeds 5MB limit")
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

// importPreviewRequested reports whether an import request asked only for a preview.
//
// Both spellings, because the dashboard sends "dryRun" and this used to read
// only "dry_run": the dashboard's "Dry Run Preview" button therefore applied
// the import it was meant to preview, and since the card only renders a diff,
// it showed nothing while doing it. ParsePagination accepts both spellings of
// pageSize for the same reason.
//
// A value that is present but not a boolean is refused rather than read as
// false. The two readings are not symmetric -- a mistaken preview is repeated,
// a mistaken import overwrites the live configuration -- so the one that
// cannot be undone must not be what a typo gets.
func importPreviewRequested(q url.Values) (bool, error) {
	dryRun := false
	for _, key := range []string{"dry_run", "dryRun"} {
		for _, v := range q[key] {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return false, fmt.Errorf("%s must be true or false, got %q", key, v)
			}
			dryRun = dryRun || b
		}
	}
	return dryRun, nil
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
