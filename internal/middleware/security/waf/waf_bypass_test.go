// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// Two ways a client used to talk its way past the WAF, both keyed on request
// data the client writes: a Content-Type naming git's smart-HTTP protocol, and a
// header that set the reputation score the engine was handed.

const sqliQuery = "/?id=1%27%20OR%20%271%27%3D%271%20--%20"

func okOrigin() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func withState(req *http.Request, rs *request.RequestState) *http.Request {
	return req.WithContext(request.WithState(req.Context(), rs))
}

// TestWAF_GitContentTypeDoesNotSkipInspection: a request only had to *claim*
// to be git traffic — a Content-Type or a path suffix, both chosen by the
// client — to skip the engine, the entropy checks and response inspection
// entirely, because every client the gateway has not seen carries the neutral
// reputation the skip was gated on.
func TestWAF_GitContentTypeDoesNotSkipInspection(t *testing.T) {
	mw, err := WAF(WAFConfig{ParanoiaLevel: 1})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	handler := mw(okOrigin())

	cases := []struct {
		name   string
		method string
		url    string
		ct     string
	}{
		{"upload-pack content type", http.MethodGet, sqliQuery, "application/x-git-upload-pack-request"},
		{"receive-pack content type", http.MethodGet, sqliQuery, "application/x-git-receive-pack-request"},
		{"upload-pack path suffix", http.MethodPost, "/repo.git/git-upload-pack" + strings.TrimPrefix(sqliQuery, "/"), "application/x-www-form-urlencoded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.url, strings.NewReader("0000"))
			req.Header.Set("Content-Type", tc.ct)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("SQLi in the query with a git %s: got %d, want 403 — the WAF was skipped on a value the client chose", tc.name, rr.Code)
			}
		})
	}
}

// TestWAF_GitPushBodyStillPassesUninspected pins the reason the exemption exists
// at all: a push is a packfile, binary and routinely larger than the body limit,
// and refusing it as oversize would break every git host behind the gateway.
// The body stays exempt; nothing else does.
func TestWAF_GitPushBodyStillPassesUninspected(t *testing.T) {
	mw, err := WAF(WAFConfig{ParanoiaLevel: 1, RequestBodyLimit: 64 << 10})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	var received int
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r.Body)
		received = buf.Len()
		w.WriteHeader(http.StatusOK)
	}))

	body := bytes.Repeat([]byte{0x78, 0x9c, 0x01, 0xff}, 40<<10) // 160 KiB, over the limit
	req := httptest.NewRequest(http.MethodPost, "/repo.git/git-receive-pack", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("git push over the body limit: got %d, want 200", rr.Code)
	}
	if received != len(body) {
		t.Fatalf("origin received %d of %d body bytes", received, len(body))
	}

	// The same body on an ordinary route is still refused as uninspectable:
	// the exemption is for git's protocol, not for large bodies.
	req = httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("oversize non-git body: got %d, want 403 (fail closed)", rr.Code)
	}
}

// TestWAF_TestReputationHeaderIsNotAClientInput: X-Gateon-Test-Reputation was
// read from every request with nothing gating it, so a client the gateway had
// scored hostile could hand the engine a clean score, drop out of the hostile
// bucket that rule 1910002 refuses, and relax the entropy threshold on the way.
// TestWAF_IPReputation already asserts the same for X-Gateon-Reputation; this
// header was the same vector under a different name.
func TestWAF_TestReputationHeaderIsNotAClientInput(t *testing.T) {
	mw, err := WAF(WAFConfig{ParanoiaLevel: 1, EnableIPReputation: true})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	handler := mw(okOrigin())

	hostile := func() *http.Request {
		return withState(httptest.NewRequest(http.MethodGet, "/", nil), &request.RequestState{Reputation: 5})
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, hostile())
	if rr.Code != http.StatusForbidden {
		t.Fatalf("hostile client without the header: got %d, want 403", rr.Code)
	}

	req := hostile()
	req.Header.Set(testReputationHeader, "100")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("hostile client asserting a clean score via %s: got %d, want 403", testReputationHeader, rr.Code)
	}

	// The hook still works for the test suites that drive the engine with it,
	// and only for them: it has to be switched on in the environment.
	t.Setenv(testReputationEnv, "1")
	req = hostile()
	req.Header.Set(testReputationHeader, "100")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("with %s set the header should be honoured: got %d, want 200", testReputationEnv, rr.Code)
	}
}
