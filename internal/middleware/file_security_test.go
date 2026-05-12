package middleware

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileSecurity_BlockedMime(t *testing.T) {
	cfg := FileSecurityConfig{
		BlockedMimeTypes: []string{"application/x-executable"},
	}
	mw := FileSecurity(cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Create a multipart request with an executable file
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "test.exe")
	// ELF header
	header := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	part.Write(header)
	part.Write(make([]byte, 64))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "File type not allowed")
}

func TestFileSecurity_AllowedMime(t *testing.T) {
	cfg := FileSecurityConfig{
		AllowedMimeTypes: []string{"image/png"},
	}
	mw := FileSecurity(cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Create a multipart request with a PNG file
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "test.png")
	// PNG header
	part.Write([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestFileSecurity_ExtensionMismatch(t *testing.T) {
	cfg := FileSecurityConfig{}
	mw := FileSecurity(cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Create a multipart request with an ELF file named as .png
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "test.png")
	// ELF header (high risk mismatch)
	header := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	part.Write(header)
	part.Write(make([]byte, 64))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "File extension mismatch")
}
