// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// fakeClamavAPI records what the uninstall handler passes through. The embedded
// interface satisfies the other GlobalAndAuthAPI methods; this test drives one
// route, so any other call would be a bug in the test rather than something to
// stub out.
type fakeClamavAPI struct {
	GlobalAndAuthAPI
	called      bool
	gotPassword string
}

func (f *fakeClamavAPI) UninstallClamav(_ context.Context, req *gateonv1.UninstallClamavRequest) (*gateonv1.UninstallClamavResponse, error) {
	f.called = true
	f.gotPassword = req.GetSudoPassword()
	return &gateonv1.UninstallClamavResponse{Success: true, Message: "ok"}, nil
}

// TestUninstallClamavPassesSudoPassword is the regression test for a sudo
// password the dashboard collected and the transport threw away.
//
// The handler used to call svc.UninstallClamav with a zero-valued request and
// never read the body at all — the install handler beside it had always decoded
// its own. So SudoPassword was always empty, and on any host where the package
// manager needs root, PreflightUninstall rejected the request with "requires
// root privileges; please provide sudo password": the exact password the
// operator had just typed. Removing ClamAV from the dashboard was impossible on
// every non-root Linux deployment, and the error blamed the user for it.
func TestUninstallClamavPassesSudoPassword(t *testing.T) {
	fake := &fakeClamavAPI{}
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, fake, &Deps{})

	req := httptest.NewRequest(http.MethodPost, "/v1/security/clamav/uninstall",
		strings.NewReader(`{"sudoPassword":"s3cret"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !fake.called {
		t.Fatal("UninstallClamav was never called")
	}
	if fake.gotPassword != "s3cret" {
		t.Errorf("SudoPassword = %q, want %q — the body was not decoded",
			fake.gotPassword, "s3cret")
	}
}

// TestUninstallClamavAcceptsEmptyBody keeps the endpoint usable without one.
// Docker mode needs no password, and a caller with nothing to send should not
// have to post "{}" to avoid a 400.
func TestUninstallClamavAcceptsEmptyBody(t *testing.T) {
	for _, body := range []string{"", "   ", "{}"} {
		fake := &fakeClamavAPI{}
		mux := http.NewServeMux()
		registerGlobalHandlers(mux, fake, &Deps{})

		req := httptest.NewRequest(http.MethodPost, "/v1/security/clamav/uninstall",
			strings.NewReader(body))
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("body %q: status = %d, want 200: %s", body, rec.Code, rec.Body.String())
			continue
		}
		if !fake.called {
			t.Errorf("body %q: UninstallClamav was never called", body)
		}
		if fake.gotPassword != "" {
			t.Errorf("body %q: SudoPassword = %q, want empty", body, fake.gotPassword)
		}
	}
}

// TestUninstallClamavRejectsMalformedBody makes sure a body that is present but
// not valid JSON is reported rather than silently treated as empty, which would
// hide a client bug behind the "no password supplied" path this test file exists
// to protect.
func TestUninstallClamavRejectsMalformedBody(t *testing.T) {
	fake := &fakeClamavAPI{}
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, fake, &Deps{})

	req := httptest.NewRequest(http.MethodPost, "/v1/security/clamav/uninstall",
		strings.NewReader(`{"sudoPassword":`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for malformed JSON", rec.Code)
	}
	if fake.called {
		t.Error("UninstallClamav was called with an undecodable body")
	}
}
