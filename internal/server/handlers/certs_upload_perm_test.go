// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/domain/proxy"
	"github.com/gsoultan/gateon/internal/middleware"
)

// certUploadAPI satisfies GlobalAndAuthAPI for the upload handler, which only
// asks for the invalidator; nothing else on the interface is reachable from it.
type certUploadAPI struct{ GlobalAndAuthAPI }

func (certUploadAPI) GetInvalidator() proxy.Invalidator { return nil }

// The paste endpoint writes 0600 because what it stores is a private key. The
// upload endpoint beside it accepts the same .key files and created them with
// os.Create — 0666 before umask, a world-readable private key under the
// default 022. Asserted on the group/other bits so a stricter umask cannot
// hide the regression by accident either way.
func TestCertUpload_PrivateKeyIsNotReadableByOthers(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", dataDir)
	mux := http.NewServeMux()
	registerCertHandlers(mux, certUploadAPI{})

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "upstream.key")
	if err != nil {
		t.Fatalf("form file: %v", err)
	}
	_, _ = part.Write([]byte("-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n"))
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/certs/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "a-1", Username: "admin", Role: auth.RoleAdmin}))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("upload: status %d body %q", rr.Code, rr.Body.String())
	}

	info, err := os.Stat(filepath.Join(dataDir, "certs", "upstream.key"))
	if err != nil {
		t.Fatalf("stat uploaded key: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("uploaded private key has mode %#o; it must not be readable by group or others", perm)
	}
}
