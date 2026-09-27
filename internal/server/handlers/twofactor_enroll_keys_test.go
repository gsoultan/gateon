// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
)

// enrollingAuth is an auth service part-way through a mandated enrollment,
// which is all POST /v1/auth/2fa/enroll asks of it.
type enrollingAuth struct {
	auth.Service
}

func (enrollingAuth) EnrollPending2FA(_, _ string) (string, string, []string, string, error) {
	return "JBSWY3DPEHPK3PXP", "data:image/png;base64,QR", []string{"recovery-1", "recovery-2"}, "user-1", nil
}

// TestTwoFactorEnrollmentAnswersUnderTheLoginPagesKeys: when an administrator
// mandates 2FA, the login page enrolls the account through this endpoint and
// renders enrollData.qrCodeUrl and enrollData.recoveryCodes. The endpoint wrote
// qr_code_url and recovery_codes, so the account saw a broken QR image and was
// never shown its recovery codes -- enrollment completed on the secret typed in
// by hand, leaving no way back in if the authenticator was lost.
func TestTwoFactorEnrollmentAnswersUnderTheLoginPagesKeys(t *testing.T) {
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, &setupGlobalsAPI{}, &Deps{AuthManager: enrollingAuth{}})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/2fa/enroll",
		strings.NewReader(`{"username":"alice","password":"first-factor"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body)
	}

	// The shape LoginPage.tsx declares for enrollData.
	var got struct {
		ID            string   `json:"id"`
		Secret        string   `json:"secret"`
		QRCodeURL     string   `json:"qrCodeUrl"`
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.QRCodeURL != "data:image/png;base64,QR" {
		t.Errorf("qrCodeUrl = %q, want the QR image; body: %s", got.QRCodeURL, rr.Body)
	}
	if len(got.RecoveryCodes) != 2 {
		t.Errorf("recoveryCodes = %q, want both codes; body: %s", got.RecoveryCodes, rr.Body)
	}
	if got.ID != "user-1" || got.Secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("id, secret = %q, %q; want the enrolling account's", got.ID, got.Secret)
	}
}
