// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/security/waf"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/gsoultan/gwaf"
)

// dlpHandler builds a response-inspecting WAF with the given action over an
// origin returning body, compressed when the request asked for it.
func dlpHandler(t *testing.T, action dlpAction, contentType, body string, compress bool) http.Handler {
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
	mw, err := WAF(WAFConfig{
		EnableDLP:                true,
		EnableResponseInspection: true,
		DLPAction:                action,
		ParanoiaLevel:            2,
		WafRules:                 store,
		ResponseBodyLimit:        1024 * 1024,
		RequestBodyLimit:         1024 * 1024,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}

	return mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		if compress && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			var out bytes.Buffer
			zw := gzip.NewWriter(&out)
			_, _ = zw.Write([]byte(body))
			_ = zw.Close()
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", strconv.Itoa(out.Len()))
			_, _ = w.Write(out.Bytes())
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write([]byte(body))
	}))
}

const (
	leakVisa       = "4111111111111111"
	leakMastercard = "5555555555554444"
	leakAWS        = "AKIAIOSFODNN7EXAMPLE"
)

func TestParseDLPAction(t *testing.T) {
	t.Setenv(dlpActionEnv, "")
	for _, tc := range []struct {
		in   string
		want dlpAction
	}{
		{"redact", dlpRedact},
		{"REDACT", dlpRedact},
		{"  redact  ", dlpRedact},
		{"audit", dlpAudit},
		{"log", dlpAudit},
		{"detect", dlpAudit},
		{"block", dlpBlock},
		{"", dlpBlock},
		// A typo must not quietly widen a security control.
		{"redakt", dlpBlock},
		{"off", dlpBlock},
		{"none", dlpBlock},
	} {
		if got := parseDLPAction(tc.in); got != tc.want {
			t.Errorf("parseDLPAction(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseDLPActionFallsBackToTheEnvironment(t *testing.T) {
	t.Setenv(dlpActionEnv, "redact")
	if got := parseDLPAction(""); got != dlpRedact {
		t.Errorf("empty config with %s=redact gave %v, want redact", dlpActionEnv, got)
	}
	// An explicit config value still wins over the environment.
	if got := parseDLPAction("block"); got != dlpBlock {
		t.Errorf("explicit block was overridden by the environment: %v", got)
	}
}

// TestDLPRedactRemovesEveryFinding is the property that makes redaction safe to
// ship: it is all of the leak or none of it. Removing the finding the engine
// happened to report and forwarding the rest would be worse than blocking,
// because it reports success.
func TestDLPRedactRemovesEveryFinding(t *testing.T) {
	body := `{"a":"` + leakVisa + `","b":"` + leakMastercard + `","c":"` + leakAWS + `","ok":"keep me"}`
	handler := dlpHandler(t, dlpRedact, "application/json", body, false)

	req := httptest.NewRequest(http.MethodGet, "/api/dump", nil)
	req.Header.Set("Accept-Encoding", "identity")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("redacting response was blocked: status %d", rec.Code)
	}
	got := rec.Body.String()
	for _, secret := range []string{leakVisa, leakMastercard, leakAWS} {
		if strings.Contains(got, secret) {
			t.Errorf("%q survived redaction: %s", secret, got)
		}
	}
	if !strings.Contains(got, "keep me") {
		t.Errorf("redaction destroyed the rest of the body: %s", got)
	}
	if n := strings.Count(got, string(redactionMarker)); n != 3 {
		t.Errorf("got %d redaction markers, want 3: %s", n, got)
	}
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(rec.Body.Len()) {
		t.Errorf("Content-Length is %s but the body is %d bytes", got, rec.Body.Len())
	}
}

// TestDLPRedactDecompressesAndForwardsPlaintext covers the compressed case. The
// held bytes are gzip, which cannot be spliced, so the redaction has to work
// from the inflated copy and the response has to go out decoded.
func TestDLPRedactDecompressesAndForwardsPlaintext(t *testing.T) {
	body := `{"card":"` + leakVisa + `","note":"keep me"}`
	handler := dlpHandler(t, dlpRedact, "application/json", body, true)

	req := httptest.NewRequest(http.MethodGet, "/api/dump", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("redacting response was blocked: status %d", rec.Code)
	}
	if enc := rec.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding is %q but the body was sent decoded", enc)
	}
	got := rec.Body.String()
	if strings.Contains(got, leakVisa) {
		t.Errorf("card survived redaction: %s", got)
	}
	if !strings.Contains(got, "keep me") {
		t.Errorf("redaction destroyed the rest of the body: %s", got)
	}
	if cl := rec.Header().Get("Content-Length"); cl != strconv.Itoa(rec.Body.Len()) {
		t.Errorf("Content-Length is %s but the body is %d bytes", cl, rec.Body.Len())
	}
}

// TestDLPAuditForwardsUntouched is the first stage of a rollout: the finding is
// recorded, the page still renders, and nobody's checkout breaks while the
// false-positive rate is being learned.
func TestDLPAuditForwardsUntouched(t *testing.T) {
	body := `{"card":"` + leakVisa + `"}`
	handler := dlpHandler(t, dlpAudit, "application/json", body, false)

	req := httptest.NewRequest(http.MethodGet, "/api/dump", nil)
	req.Header.Set("Accept-Encoding", "identity")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("audit mode blocked the response: status %d", rec.Code)
	}
	if rec.Body.String() != body {
		t.Errorf("audit mode changed the body: got %q, want %q", rec.Body.String(), body)
	}
}

// TestDLPBlockIsStillTheDefault guards against the new actions changing what an
// existing install does.
func TestDLPBlockIsStillTheDefault(t *testing.T) {
	body := `{"card":"` + leakVisa + `"}`
	handler := dlpHandler(t, dlpBlock, "application/json", body, false)

	req := httptest.NewRequest(http.MethodGet, "/api/dump", nil)
	req.Header.Set("Accept-Encoding", "identity")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("default action did not block: status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), leakVisa) {
		t.Error("card reached the client")
	}
}

// TestDLPRedactDoesNotApplyToTheRestOfTheCorpus is the containment property. An
// injection is not made safe by deleting the matched bytes, so the action has to
// stop at the data-leak rules.
func TestDLPRedactDoesNotApplyToTheRestOfTheCorpus(t *testing.T) {
	d, dialect, _ := db.Open("sqlite::memory:")
	_ = db.Migrate(d, dialect)
	store := waf.NewStore(d)
	if err := store.Seed(t.Context()); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	mw, err := WAF(WAFConfig{
		EnableDLP:                true,
		EnableResponseInspection: true,
		DLPAction:                dlpRedact,
		ParanoiaLevel:            2,
		WafRules:                 store,
		ResponseBodyLimit:        1024 * 1024,
		RequestBodyLimit:         1024 * 1024,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet,
		"/search?q=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("SQL injection was not blocked with the redact action set: status %d", rec.Code)
	}
}

// TestDLPRedactorMergesOverlappingFindings covers the splice arithmetic. Two
// detectors matching across the same bytes — a connection string that is also a
// credential — must produce one marker, not two overlapping cuts.
func TestDLPRedactorMergesOverlappingFindings(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spans []byteSpan
		want  []byteSpan
	}{
		{"disjoint", []byteSpan{{0, 3}, {5, 8}}, []byteSpan{{0, 3}, {5, 8}}},
		{"overlapping", []byteSpan{{0, 6}, {4, 9}}, []byteSpan{{0, 9}}},
		{"contained", []byteSpan{{0, 10}, {3, 5}}, []byteSpan{{0, 10}}},
		{"touching", []byteSpan{{0, 4}, {4, 8}}, []byteSpan{{0, 8}}},
		{"unsorted", []byteSpan{{7, 9}, {0, 2}}, []byteSpan{{0, 2}, {7, 9}}},
		{"single", []byteSpan{{2, 4}}, []byteSpan{{2, 4}}},
		{"empty", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeSpans(append([]byteSpan(nil), tc.spans...))
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// TestRedactionThatFindsNothingRefusesTheResponse is the failure mode that
// would be silent. If the engine reports a leak the redactor cannot locate —
// a rule with a transform, a target other than the body, a corpus that has
// drifted — then forwarding the body ships the leak while reporting it handled.
// The fallback has to be the block the operator was trying to avoid.
func TestRedactionThatFindsNothingRefusesTheResponse(t *testing.T) {
	const leak = "card 4111111111111111 in the clear"

	rec := httptest.NewRecorder()
	w := &wafResponseWriter{
		ResponseWriter: rec,
		routeID:        "test",
		dlpAction:      dlpRedact,
		// A redactor with no detectors: it will locate nothing.
		redactor:      &dlpRedactor{},
		buf:           bytes.NewBufferString(leak),
		bufLimit:      1024,
		redactPending: true,
		respEnc:       encodingIdentity,
	}

	w.resolveRedaction()

	if !w.blocked {
		t.Fatal("a redaction that removed nothing forwarded the response")
	}
	if w.redacted != nil {
		t.Error("a failed redaction produced a body to send")
	}
	if body := rec.Body.String(); strings.Contains(body, "4111111111111111") {
		t.Errorf("the leak reached the client: %q", body)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestRedactionIsObservedExactlyOnce pins the accounting. The decision is held
// back while redaction is attempted, so the paths that report it — success and
// the block fallback — must not both fire.
func TestRedactionIsObservedExactlyOnce(t *testing.T) {
	for _, tc := range []struct {
		name     string
		redactor *dlpRedactor
	}{
		{"redaction succeeds", newDLPRedactor(2)},
		{"redaction finds nothing", &dlpRedactor{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var observed int
			w := &wafResponseWriter{
				ResponseWriter: httptest.NewRecorder(),
				routeID:        "test",
				dlpAction:      dlpRedact,
				redactor:       tc.redactor,
				buf:            bytes.NewBufferString("card " + leakVisa + " here"),
				bufLimit:       1024,
				redactPending:  true,
				respEnc:        encodingIdentity,
				onDecision:     func(gwaf.Decision) { observed++ },
			}

			w.resolveRedaction()

			if observed != 1 {
				t.Errorf("decision observed %d times, want exactly 1", observed)
			}
		})
	}
}

// TestDLPActionFlowsFromTheGlobalConfig closes the loop the proto field exists
// for. A knob that is settable in the dashboard but never read is the failure
// mode worth a test: the value has to survive proto -> WAFConfig -> the writer.
func TestDLPActionFlowsFromTheGlobalConfig(t *testing.T) {
	t.Setenv(dlpActionEnv, "")

	for _, tc := range []struct {
		proto string
		want  dlpAction
	}{
		{"redact", dlpRedact},
		{"audit", dlpAudit},
		{"block", dlpBlock},
		{"", dlpBlock},
		{"nonsense", dlpBlock},
	} {
		t.Run("proto="+tc.proto, func(t *testing.T) {
			w := &gateonv1.WafConfig{Enabled: true, Dlp: true, DlpAction: tc.proto}
			if got := parseDLPAction(w.GetDlpAction()); got != tc.want {
				t.Errorf("proto dlp_action %q produced %v, want %v", tc.proto, got, tc.want)
			}
		})
	}
}

// TestDLPActionIsInTheConfigFingerprint stops two policies that differ only in
// what they do about a leak from sharing a cached engine — which would mean the
// first route to compile decided the behaviour for every route after it.
func TestDLPActionIsInTheConfigFingerprint(t *testing.T) {
	base := WAFConfig{EnableDLP: true, EnableResponseInspection: true}

	seen := make(map[string]dlpAction, 3)
	for _, action := range []dlpAction{dlpBlock, dlpRedact, dlpAudit} {
		cfg := base
		cfg.DLPAction = action
		fp := cfg.Fingerprint()
		if prev, dup := seen[fp]; dup {
			t.Errorf("actions %v and %v share fingerprint %s", prev, action, fp)
		}
		seen[fp] = action
	}
}
