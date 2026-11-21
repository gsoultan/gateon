// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

var initAuditOnce sync.Once

// recordAudit puts a real audit log under this test binary -- once, since the
// audit log is process-global -- and collects what it stores for this test.
//
// The log's configuration is process-global too, and any test that saves the
// global settings through the API applies theirs: the global-secrets tests
// save an audit section with Enabled unset, which switches the log off. Under
// -shuffle those ran first often enough to fail CI, so every caller turns the
// log back on rather than trusting whoever ran before it.
func recordAudit(t *testing.T) func() []audit.AuditEntry {
	t.Helper()
	initAuditOnce.Do(func() {
		dir, err := os.MkdirTemp("", "gateon-handlers-audit-*")
		if err != nil {
			t.Fatal(err)
		}
		if err := audit.Init(&gateonv1.AuditConfig{Enabled: true}, "sqlite:"+filepath.Join(dir, "audit.db")); err != nil {
			t.Fatal(err)
		}
	})
	audit.UpdateConfig(&gateonv1.AuditConfig{Enabled: true})
	var mu sync.Mutex
	var got []audit.AuditEntry
	remove := audit.AddSink(func(e audit.AuditEntry) {
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
	})
	t.Cleanup(remove)
	return func() []audit.AuditEntry {
		mu.Lock()
		defer mu.Unlock()
		return append([]audit.AuditEntry(nil), got...)
	}
}

func asAdmin(req *http.Request) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "a-1", Username: "admin", Role: auth.RoleAdmin}))
}

func uploadCert(t *testing.T, mux *http.ServeMux, name string, content []byte) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(content)
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/v1/certs/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, asAdmin(req))
	if rr.Code != http.StatusOK {
		t.Fatalf("upload: status %d body %q", rr.Code, rr.Body.String())
	}
}

func certEntries(entries []audit.AuditEntry) []audit.AuditEntry {
	var out []audit.AuditEntry
	for _, e := range entries {
		if e.Resource == "certificate" {
			out = append(out, e)
		}
	}
	return out
}

// Uploading a key with the name of one in use replaces the key a listener
// serves. It wrote no audit entry, so a stolen session could swap it unseen.
func TestCertUpload_IsAuditedAndSaysWhenItReplaced(t *testing.T) {
	entries := recordAudit(t)
	t.Setenv("GATEON_DATA_DIR", t.TempDir())
	mux := http.NewServeMux()
	registerCertHandlers(mux, certUploadAPI{})

	first := []byte("-----BEGIN PRIVATE KEY-----\nfirst\n-----END PRIVATE KEY-----\n")
	second := []byte("-----BEGIN PRIVATE KEY-----\nsecond\n-----END PRIVATE KEY-----\n")
	uploadCert(t, mux, "site.key", first)
	uploadCert(t, mux, "site.key", second)

	got := certEntries(entries())
	if len(got) != 2 {
		t.Fatalf("got %d certificate audit entries, want 2: %+v", len(got), got)
	}
	if got[0].UserID != "admin" || got[0].Action != "upload" {
		t.Fatalf("entry = %+v, want user admin, action upload", got[0])
	}
	if !strings.HasPrefix(got[0].Details, "Wrote certs/site.key") {
		t.Fatalf("first upload details = %q, want it to say it wrote the file", got[0].Details)
	}
	if !strings.HasPrefix(got[1].Details, "Replaced certs/site.key") {
		t.Fatalf("second upload details = %q, want it to say it replaced the file", got[1].Details)
	}
	if want := fmt.Sprintf("%x", sha256.Sum256(second)); !strings.Contains(got[1].Details, want) {
		t.Fatalf("details %q do not carry the written file's sha256 %s", got[1].Details, want)
	}
	if strings.Contains(got[1].Details, "second") {
		t.Fatal("the audit entry carries the key's content")
	}
}

func TestCertPaste_IsAudited(t *testing.T) {
	entries := recordAudit(t)
	t.Setenv("GATEON_DATA_DIR", t.TempDir())
	mux := http.NewServeMux()
	registerCertHandlers(mux, certUploadAPI{})

	b, _ := json.Marshal(map[string]string{"content": "-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n", "type": "key"})
	req := httptest.NewRequest(http.MethodPost, "/v1/certs/paste", bytes.NewReader(b))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, asAdmin(req))
	if rr.Code != http.StatusOK {
		t.Fatalf("paste: status %d body %q", rr.Code, rr.Body.String())
	}
	got := certEntries(entries())
	if len(got) != 1 || got[0].Action != "paste" || !strings.Contains(got[0].Details, "certs/") {
		t.Fatalf("certificate audit entries = %+v, want one paste entry naming the file", got)
	}
}
