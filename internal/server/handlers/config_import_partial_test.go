// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// refusingMiddlewares saves every middleware except the one it is told to
// refuse, the way the real save refuses a config its build check rejects.
type refusingMiddlewares struct {
	recMiddlewares
	refuse string
}

func (f refusingMiddlewares) SaveMiddleware(ctx context.Context, mw *gateonv1.Middleware) error {
	if mw.GetId() == f.refuse {
		return errors.New(`middleware config "trust_cloudflare_headers": "true" is not valid`)
	}
	return f.recMiddlewares.SaveMiddleware(ctx, mw)
}

const partialImportBody = `{
  "services":     [{"id": "svc-1", "name": "backend", "weighted_targets": [{"url": "http://10.0.0.1:80"}]}],
  "entry_points": [{"id": "ep-1", "name": "web", "address": ":443"}],
  "middlewares":  [{"id": "mw-ok", "name": "cors", "type": "cors"},
                   {"id": "mw-bad", "name": "cloudflare", "type": "ipfilter",
                    "config": {"trust_cloudflare_headers": "true"}}],
  "routes":       [{"id": "rt-1", "rule": "Host(` + "`a.example.com`" + `)", "service_id": "svc-1"}]
}`

// TestConfigImportReportsWhatAPartialImportApplied is the import of a real
// exported config in which one middleware is refused.
//
// The import is item by item: the refusal does not stop the service,
// entrypoint, other middleware and route around it, which are written and
// live. The response used to carry only the refusal, and the dashboard --
// which treats any error as the outcome -- showed that alone and kept its
// cached, pre-import lists. The operator saw an import that had added
// nothing, while it had added all but one item.
func TestConfigImportReportsWhatAPartialImportApplied(t *testing.T) {
	rec := &importRecorder{}
	d := &Deps{
		RouteService:   recRoutes{rec: rec},
		ServiceService: recServices{rec: rec},
		EpService:      recEntryPoints{rec: rec},
		MwService:      refusingMiddlewares{recMiddlewares: recMiddlewares{rec: rec}, refuse: "mw-bad"},
	}
	mux := http.NewServeMux()
	registerConfigImportExport(mux, d)

	req := httptest.NewRequest(http.MethodPost, "/v1/config/import", strings.NewReader(partialImportBody))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, authWaived(req))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body)
	}
	var out importResult
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", rr.Body, err)
	}
	want := importCounts{Routes: 1, Services: 1, EntryPoints: 1, Middlewares: 1}
	if out.Applied != want {
		t.Errorf("applied = %+v, want %+v: the response must say what the import wrote, "+
			"not only what it refused (saved: %v)", out.Applied, want, rec.saved)
	}
	if len(out.Errors) != 1 || !strings.Contains(out.Errors[0], "middleware mw-bad") {
		t.Errorf("errors = %v, want the one refused middleware named", out.Errors)
	}
	if !out.Success {
		t.Error("success = false for an import that applied four of five items")
	}
}

// TestConfigImportFailsWhenNothingApplies keeps success honest the other way:
// an import whose every item is refused did nothing, and must not say otherwise.
func TestConfigImportFailsWhenNothingApplies(t *testing.T) {
	d := &Deps{MwService: refusingMiddlewares{refuse: "only"}}
	res := runConfigImport(context.Background(), d, &configExport{
		Middlewares: []*gateonv1.Middleware{{Id: "only"}},
	})
	if res.Success || res.Applied.total() != 0 || len(res.Errors) != 1 {
		t.Errorf("result = %+v, want a failure with one refusal and nothing applied", res)
	}
}
