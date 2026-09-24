// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/domain/entrypoint"
	domainmw "github.com/gsoultan/gateon/internal/domain/middleware"
	"github.com/gsoultan/gateon/internal/domain/route"
	"github.com/gsoultan/gateon/internal/domain/service"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// importRecorder stands in for the four domain services an import writes
// through, and records every save. It holds nothing, so a dry run's diff
// reports everything as created.
type importRecorder struct {
	saved []string
}

type recRoutes struct {
	route.Service
	rec *importRecorder
}

func (f recRoutes) GetRoute(context.Context, string) (*gateonv1.Route, bool) { return nil, false }
func (f recRoutes) SaveRoute(_ context.Context, rt *gateonv1.Route) error {
	f.rec.saved = append(f.rec.saved, "route "+rt.Id)
	return nil
}

type recServices struct {
	service.Service
	rec *importRecorder
}

func (f recServices) GetService(context.Context, string) (*gateonv1.Service, bool) {
	return nil, false
}
func (f recServices) SaveService(_ context.Context, svc *gateonv1.Service) error {
	f.rec.saved = append(f.rec.saved, "service "+svc.Id)
	return nil
}

type recEntryPoints struct {
	entrypoint.Service
	rec *importRecorder
}

func (f recEntryPoints) GetEntryPoint(context.Context, string) (*gateonv1.EntryPoint, bool) {
	return nil, false
}
func (f recEntryPoints) SaveEntryPoint(_ context.Context, ep *gateonv1.EntryPoint) error {
	f.rec.saved = append(f.rec.saved, "entrypoint "+ep.Id)
	return nil
}

type recMiddlewares struct {
	domainmw.Service
	rec *importRecorder
}

func (f recMiddlewares) GetMiddleware(context.Context, string) (*gateonv1.Middleware, bool) {
	return nil, false
}
func (f recMiddlewares) SaveMiddleware(_ context.Context, mw *gateonv1.Middleware) error {
	f.rec.saved = append(f.rec.saved, "middleware "+mw.Id)
	return nil
}

func importMux(rec *importRecorder) *http.ServeMux {
	d := &Deps{
		RouteService:   recRoutes{rec: rec},
		ServiceService: recServices{rec: rec},
		EpService:      recEntryPoints{rec: rec},
		MwService:      recMiddlewares{rec: rec},
	}
	mux := http.NewServeMux()
	registerConfigImportExport(mux, d)
	return mux
}

const importBody = `{
  "services": [{"id": "svc-1", "name": "backend", "weighted_targets": [{"url": "http://10.0.0.1:80"}]}],
  "routes":   [{"id": "rt-1", "rule": "Host(` + "`a.example.com`" + `)", "service_id": "svc-1"}]
}`

func postImport(t *testing.T, mux *http.ServeMux, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/config/import"+query, strings.NewReader(importBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestConfigImportDryRunWritesNothing is the dashboard's "Dry Run Preview"
// button, sent the way the button sends it.
//
// ConfigImportExportCard posts to /v1/config/import?dryRun=true. If the server
// does not recognise that as a dry run, the preview is the import: every route,
// service, entrypoint and middleware in the file is written, the response
// carries no diff, and the card -- which only renders a diff -- shows nothing at
// all. The operator was asking what the file would change and got the change.
func TestConfigImportDryRunWritesNothing(t *testing.T) {
	for _, query := range []string{"?dryRun=true", "?dry_run=true"} {
		t.Run(query, func(t *testing.T) {
			rec := &importRecorder{}
			rr := postImport(t, importMux(rec), query)

			if len(rec.saved) != 0 {
				t.Fatalf("a dry run (%s) wrote %v to the live configuration", query, rec.saved)
			}
			if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"diff"`) {
				t.Errorf("dry run answered %d %s; the dashboard renders the diff and "+
					"shows nothing without one", rr.Code, rr.Body.String())
			}
		})
	}
}

// TestConfigImportRefusesADryRunFlagItCannotRead covers the typo. A preview
// flag the server cannot parse must not be read as "apply": the two outcomes
// are not symmetric, and only one of them can be undone by trying again.
func TestConfigImportRefusesADryRunFlagItCannotRead(t *testing.T) {
	rec := &importRecorder{}
	rr := postImport(t, importMux(rec), "?dry_run=yes-please")

	if len(rec.saved) != 0 {
		t.Fatalf("an unreadable dry_run value applied the import: %v", rec.saved)
	}
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an unreadable dry_run value", rr.Code)
	}
}

// TestConfigImportWithoutDryRunApplies proves the recorder can see a write, so
// the two tests above are not passing because nothing is ever recorded.
func TestConfigImportWithoutDryRunApplies(t *testing.T) {
	rec := &importRecorder{}
	rr := postImport(t, importMux(rec), "")

	if rr.Code != http.StatusOK {
		t.Fatalf("import answered %d: %s", rr.Code, rr.Body.String())
	}
	want := []string{"service svc-1", "route rt-1"}
	if strings.Join(rec.saved, ",") != strings.Join(want, ",") {
		t.Errorf("saved %v, want %v", rec.saved, want)
	}
}
