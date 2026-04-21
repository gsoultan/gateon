package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type mockGlobalStore struct{}

func (m *mockGlobalStore) Get(ctx context.Context) *gateonv1.GlobalConfig {
	return &gateonv1.GlobalConfig{
		Geoip: &gateonv1.GeoIPConfig{
			Enabled:           true,
			MaxmindLicenseKey: "test-key",
		},
	}
}
func (m *mockGlobalStore) Update(ctx context.Context, conf *gateonv1.GlobalConfig) error { return nil }
func (m *mockGlobalStore) ConfigFileExists() bool                                        { return true }

func TestGeoIPUploadSuccess(t *testing.T) {
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	tempDir := t.TempDir()
	t.Cleanup(func() {
		_ = os.Chdir(oldWD)
	})
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}

	mux := http.NewServeMux()
	registerGeoIPHandlers(mux, &mockGlobalStore{})

	req := newGeoIPUploadRequest(t, "GeoLite2-Country.mmdb", []byte("mmdb-content"), nil)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Path == "" {
		t.Fatalf("empty uploaded path")
	}

	got, err := os.ReadFile(resp.Path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", resp.Path, err)
	}
	if string(got) != "mmdb-content" {
		t.Fatalf("uploaded content = %q, want %q", string(got), "mmdb-content")
	}

	wantPath := filepath.Join("geoip", "GeoLite2-Country.mmdb")
	if resp.Path != wantPath {
		t.Fatalf("uploaded path = %q, want %q", resp.Path, wantPath)
	}
}

func TestGeoIPUploadRejectsInvalidExtension(t *testing.T) {
	mux := http.NewServeMux()
	registerGeoIPHandlers(mux, &mockGlobalStore{})

	req := newGeoIPUploadRequest(t, "not-mmdb.txt", []byte("ignored"), nil)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if rr.Body.String() != "invalid file type" {
		t.Fatalf("response body = %q, want %q", rr.Body.String(), "invalid file type")
	}
}

func TestGeoIPUploadRequiresWritePermission(t *testing.T) {
	mux := http.NewServeMux()
	registerGeoIPHandlers(mux, &mockGlobalStore{})

	claims := &auth.Claims{ID: "viewer-1", Username: "viewer", Role: auth.RoleViewer}
	req := newGeoIPUploadRequest(t, "GeoLite2-Country.mmdb", []byte("ignored"), claims)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func newGeoIPUploadRequest(t *testing.T, filename string, content []byte, claims *auth.Claims) *http.Request {
	t.Helper()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := io.Copy(part, bytes.NewReader(content)); err != nil {
		t.Fatalf("write file content: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("multipart close: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/geoip/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if claims == nil {
		return req
	}

	ctx := context.WithValue(t.Context(), middleware.UserContextKey, claims)
	return req.WithContext(ctx)
}
