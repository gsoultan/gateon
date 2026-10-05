// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

const bindingBuild = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cr0200_7e33b58890ac"

// bindingRoute is tls_binding behind the reputation blocker every route
// carries, with reputation enabled and a telemetry store of its own.
func bindingRoute(t *testing.T) http.Handler {
	t.Helper()
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "binding.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(t.Context()) })
	var reached bool
	return ReputationBlocker("binding-route")(bindingHandler(&reached))
}

// sendBound serves one request from ip with cert-A and the Cookie header
// cookies, and returns what the client got.
func sendBound(h http.Handler, ip, cookies string) *httptest.ResponseRecorder {
	r := withPeer(httptest.NewRequest(http.MethodGet, "https://x/account", nil), []byte("cert-A"))
	r.RemoteAddr = ip + ":40000"
	r.Header.Set("Cookie", cookies)
	r = r.WithContext(request.WithState(r.Context(), &request.RequestState{JA4Plus: bindingBuild}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	telemetry.FlushThreats()
	return rec
}

// TestADuplicateSessionCookieIsRefusedAndNotHeldAgainstTheClient: a browser
// holds the session cookie under two paths once a backend changes the
// cookie's Path, and sends both. tls_binding refuses that, since a backend may
// read either copy (TRUTH-NEW-5), and the refusal was a score-80 threat held
// against the client: on the third such request the reputation blocker
// refused the client on every route. It is refused and recorded observed
// (ADR 0059). A binding for another certificate is still held against it.
func TestADuplicateSessionCookieIsRefusedAndNotHeldAgainstTheClient(t *testing.T) {
	h := bindingRoute(t)
	b := tlsBinder{cookie: "session", binding: "session_binding", secret: testSecret}
	certA, certB := sha256.Sum256([]byte("cert-A")), sha256.Sum256([]byte("cert-B"))
	const user, thief = "100.64.80.10", "100.64.81.10"
	t.Cleanup(func() {
		telemetry.ResetReputation(repid.For(bindingBuild, user))
		telemetry.ResetReputation(repid.For(bindingBuild, thief))
	})

	twice := "session=OWN; session=OWN; session_binding=" + b.mac(certA[:], "OWN")
	for n := range 4 {
		rec := sendBound(h, user, twice)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "binding mismatch") {
			t.Fatalf("duplicate cookie request %d: %d %q, want tls_binding's own 403: the refusals "+
				"before it were held against the client", n+1, rec.Code, rec.Body.String())
		}
	}
	if got := telemetry.GetReputationScore(repid.For(bindingBuild, user)); got != 100 {
		t.Errorf("refused duplicate cookies moved the client's score to %v", got)
	}

	stolen := "session=STOLEN; session_binding=" + b.mac(certB[:], "STOLEN")
	if rec := sendBound(h, thief, stolen); rec.Code != http.StatusForbidden {
		t.Fatalf("a session bound to another certificate got %d, want 403", rec.Code)
	}
	if got := telemetry.GetReputationScore(repid.For(bindingBuild, thief)); got >= 100 {
		t.Errorf("a binding mismatch left the presenter's score at %v: a stolen cookie is evidence", got)
	}
}
