// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gateon/internal/security/waf/apischema"
	"github.com/gsoultan/gateon/internal/telemetry"
	dto "github.com/prometheus/client_model/go"
)

const ordersOpenAPI = `
openapi: 3.0.3
info: {title: Orders, version: "1"}
paths:
  /api/v1/orders:
    get:
      parameters:
        - {name: id, in: query, schema: {type: integer}}
        - {name: status, in: query, schema: {type: string, enum: [pending, shipped]}}
        - {name: note, in: query, schema: {type: string, maxLength: 200}}
`

// openAPIWAF builds a route WAF from the config keys an operator sets, so the
// keys themselves are under test, and reports whether the origin was reached.
func openAPIWAF(t *testing.T, cfg map[string]string) (http.Handler, *int) {
	t.Helper()
	d, dialect, err := db.Open("sqlite::memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Migrate(d, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := waf.NewStore(d)
	if err := store.Seed(t.Context()); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	wafCfg := parseWAFConfig(cfg)
	wafCfg.WafRules = store
	mw, err := WAF(wafCfg)
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	reached := new(int)
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached++
		w.WriteHeader(http.StatusOK)
	})), reached
}

func schemaViolations(t *testing.T, route, violation, mode string) float64 {
	t.Helper()
	c, err := telemetry.MiddlewareWAFSchemaViolationsTotal.GetMetricWithLabelValues(route, violation, mode)
	if err != nil {
		t.Fatalf("counter: %v", err)
	}
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return m.GetCounter().GetValue()
}

func statusOf(h http.Handler, target string) int {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec.Code
}

// TestOpenAPIRecordModeCountsAndForwards is the default: a request outside the
// document reaches the origin and is counted, and the rules still refuse an
// attack -- including one in the very field that broke the document.
func TestOpenAPIRecordModeCountsAndForwards(t *testing.T) {
	const route = "openapi-record"
	h, reached := openAPIWAF(t, map[string]string{"route": route, keyOpenAPISpec: ordersOpenAPI})

	before := schemaViolations(t, route, "type_mismatch", apischema.ModeRecord)
	if code := statusOf(h, "/api/v1/orders?id=A-1042"); code != http.StatusOK || *reached != 1 {
		t.Fatalf("out-of-document request: status %d, origin reached %d times; want 200 and once", code, *reached)
	}
	if got := schemaViolations(t, route, "type_mismatch", apischema.ModeRecord) - before; got != 1 {
		t.Errorf("violations counted = %v, want 1", got)
	}

	if code := statusOf(h, "/api/v1/orders?id=42&status=shipped"); code != http.StatusOK {
		t.Errorf("in-document request: status %d, want 200", code)
	}
	if got := schemaViolations(t, route, "type_mismatch", apischema.ModeRecord) - before; got != 1 {
		t.Errorf("an in-document request was counted as a violation (total %v)", got)
	}

	*reached = 0
	if code := statusOf(h, "/api/v1/orders?id=1+UNION+SELECT+password+FROM+users--"); code != http.StatusForbidden || *reached != 0 {
		t.Errorf("attack in the violating field: status %d, origin reached %d times; want 403 and never", code, *reached)
	}
}

// TestOpenAPIEnforceModeRefuses: the same request, with the mode set.
func TestOpenAPIEnforceModeRefuses(t *testing.T) {
	const route = "openapi-enforce"
	h, reached := openAPIWAF(t, map[string]string{
		"route": route, keyOpenAPISpec: ordersOpenAPI, keyOpenAPIMode: apischema.ModeEnforce,
	})

	before := schemaViolations(t, route, "not_in_enum", apischema.ModeEnforce)
	if code := statusOf(h, "/api/v1/orders?status=deleted"); code != http.StatusForbidden || *reached != 0 {
		t.Fatalf("out-of-document request: status %d, origin reached %d times; want 403 and never", code, *reached)
	}
	if got := schemaViolations(t, route, "not_in_enum", apischema.ModeEnforce) - before; got != 1 {
		t.Errorf("violations counted = %v, want 1", got)
	}
	if code := statusOf(h, "/api/v1/orders?status=shipped"); code != http.StatusOK || *reached != 1 {
		t.Errorf("in-document request: status %d, origin reached %d times; want 200 and once", code, *reached)
	}
	// A path the document does not describe is not a violation: the document
	// describes what it describes, and the route may serve more.
	if code := statusOf(h, "/healthz"); code != http.StatusOK {
		t.Errorf("undescribed path: status %d, want 200", code)
	}
}

// TestOpenAPIEnforcedRefusalIsHeldAgainstNobody: a client one release behind
// the document sends a request outside it. Counting that as a WAF block would
// let enforcing a document shun the API's own users.
func TestOpenAPIEnforcedRefusalIsHeldAgainstNobody(t *testing.T) {
	h, _ := openAPIWAF(t, map[string]string{
		"route": "openapi-rep", keyOpenAPISpec: ordersOpenAPI, keyOpenAPIMode: apischema.ModeEnforce,
	})
	const client = "203.0.113.77"
	blocks := func() float64 { return wafBlocksFor(client) }
	before := blocks()
	for range 5 {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/orders?id=abc", nil)
		req.RemoteAddr = client + ":40000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status %d, want 403", rec.Code)
		}
	}
	if got := blocks() - before; got != 0 {
		t.Errorf("%v WAF blocks recorded against the client for schema refusals, want 0", got)
	}
}

// TestOpenAPIAuditOnlyNeverRefuses: audit-only refuses nothing, whatever the
// document's mode says, and the violation is counted as recorded.
func TestOpenAPIAuditOnlyNeverRefuses(t *testing.T) {
	const route = "openapi-audit"
	h, reached := openAPIWAF(t, map[string]string{
		"route": route, "audit_only": "true",
		keyOpenAPISpec: ordersOpenAPI, keyOpenAPIMode: apischema.ModeEnforce,
	})
	before := schemaViolations(t, route, "type_mismatch", apischema.ModeRecord)
	if code := statusOf(h, "/api/v1/orders?id=abc"); code != http.StatusOK || *reached != 1 {
		t.Fatalf("status %d, origin reached %d times; want 200 and once", code, *reached)
	}
	if got := schemaViolations(t, route, "type_mismatch", apischema.ModeRecord) - before; got != 1 {
		t.Errorf("violations counted as recorded = %v, want 1", got)
	}
}

// TestOpenAPIBadSettingFailsTheBuild: the middleware service builds the WAF
// before it saves one, so an error here is a refused save. Loading instead
// would leave a route whose form shows a document and whose engine checks
// nothing.
func TestOpenAPIBadSettingFailsTheBuild(t *testing.T) {
	for name, cfg := range map[string]map[string]string{
		"not an OpenAPI document": {keyOpenAPISpec: "hello: world"},
		"no operations":           {keyOpenAPISpec: "openapi: 3.0.3\ninfo: {title: x, version: \"1\"}\npaths: {}"},
		"unknown mode":            {keyOpenAPISpec: ordersOpenAPI, keyOpenAPIMode: "enforced"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := WAF(parseWAFConfig(cfg)); err == nil {
				t.Error("the WAF was built from a setting it cannot honour")
			}
		})
	}
}

// TestOpenAPIIsPartOfTheFingerprint: engines are cached by fingerprint, so a
// document or mode left out of it means the first route built wins.
func TestOpenAPIIsPartOfTheFingerprint(t *testing.T) {
	none := parseWAFConfig(map[string]string{}).Fingerprint()
	record := parseWAFConfig(map[string]string{keyOpenAPISpec: ordersOpenAPI}).Fingerprint()
	enforce := parseWAFConfig(map[string]string{keyOpenAPISpec: ordersOpenAPI, keyOpenAPIMode: "enforce"}).Fingerprint()
	other := parseWAFConfig(map[string]string{keyOpenAPISpec: strings.Replace(ordersOpenAPI, "integer", "string", 1)}).Fingerprint()
	seen := map[string]string{}
	for name, fp := range map[string]string{"none": none, "record": record, "enforce": enforce, "other document": other} {
		if prev, dup := seen[fp]; dup {
			t.Errorf("%q and %q share a fingerprint", name, prev)
		}
		seen[fp] = name
	}
}

func TestSchemaExplanationBoundsTheClientChosenName(t *testing.T) {
	got := schemaExplanation("undeclared_parameter: " + strings.Repeat("a", 4000))
	if len(got) > maxSchemaDetail+80 {
		t.Errorf("explanation is %d bytes; a client-chosen name was not bounded", len(got))
	}
}
