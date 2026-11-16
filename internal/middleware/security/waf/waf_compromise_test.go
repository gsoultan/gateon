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
)

const (
	accountFile = "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
	cardOnAPage = "paid with 4111 1111 1111 1111\n"
)

// compromiseHandler is a WAF with response inspection in front of an origin
// that answers an unremarkable request with body.
func compromiseHandler(t *testing.T, action dlpAction, body string) http.Handler {
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
		WafRules:                 store,
		ResponseBodyLimit:        1 << 20,
		RequestBodyLimit:         1 << 20,
	})
	if err != nil {
		t.Fatalf("create WAF: %v", err)
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}))
}

func fetch(h http.Handler) *httptest.ResponseRecorder {
	// Nothing in the request matches a rule: the point of these rules is the
	// exploit the request side did not recognise.
	req := httptest.NewRequest(http.MethodGet, "/download?file=report.pdf", nil)
	req.Header.Set("Accept-Encoding", "identity")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestWAF_ResponseShowingACompromiseIsRefused: the request is clean and the
// response is an account file, so the only place to stop it is the response.
func TestWAF_ResponseShowingACompromiseIsRefused(t *testing.T) {
	for name, body := range map[string]string{
		"account file":    accountFile,
		"id output":       "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n",
		"win.ini":         "; for 16-bit app support\r\n[fonts]\r\n[extensions]\r\n[mci extensions]\r\n",
		"role credential": `{"Code":"Success","Type":"AWS-HMAC","AccessKeyId":"ASIA` + `EXAMPLEEXAMPLE00","Expiration":"2026-11-16T20:00:00Z"}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := fetch(compromiseHandler(t, dlpBlock, body))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403; body %q", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), body[:12]) {
				t.Error("the refused response still carries the origin's body")
			}
		})
	}
}

// TestWAF_OrdinaryResponseIsNotTakenForACompromise is the other half: prose
// that mentions these things is not the thing.
func TestWAF_OrdinaryResponseIsNotTakenForACompromise(t *testing.T) {
	for name, body := range map[string]string{
		"prose about the file":  "The /etc/passwd file lists accounts, one per line, starting with root.\n",
		"one account-like line": "contact: root:x at example dot org\n",
		"a user id in a log":    "request by uid=1042 completed in 12ms\n",
	} {
		t.Run(name, func(t *testing.T) {
			rec := fetch(compromiseHandler(t, dlpBlock, body))
			if rec.Code != http.StatusOK || rec.Body.String() != body {
				t.Errorf("status %d body %q, want the origin's response unchanged", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestWAF_CompromiseIsRefusedNotRedacted: under dlp_action=redact a card number
// is cut out and the page forwarded. An account file treated the same way
// loses the two lines the rule matched and the rest reaches the client.
func TestWAF_CompromiseIsRefusedNotRedacted(t *testing.T) {
	t.Run("account file alone", func(t *testing.T) {
		rec := fetch(compromiseHandler(t, dlpRedact, accountFile))
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "www-data") {
			t.Errorf("status %d body %q, want a refusal carrying none of the file", rec.Code, rec.Body.String())
		}
	})
	t.Run("account file beside a card number", func(t *testing.T) {
		rec := fetch(compromiseHandler(t, dlpRedact, cardOnAPage+accountFile))
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "www-data") {
			t.Errorf("status %d body %q, want a refusal carrying none of the file", rec.Code, rec.Body.String())
		}
	})
	t.Run("card number alone is still redacted", func(t *testing.T) {
		rec := fetch(compromiseHandler(t, dlpRedact, cardOnAPage))
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "4111") ||
			!strings.Contains(rec.Body.String(), "[REDACTED]") {
			t.Errorf("status %d body %q, want the page with the number redacted", rec.Code, rec.Body.String())
		}
	})
}
