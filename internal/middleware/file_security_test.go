package middleware

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// uploadRequest builds a multipart POST request with a single file part.
func uploadRequest(t *testing.T, fieldName, fileName string, content []byte) *http.Request {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile(fieldName, fileName)
	require.NoError(t, err)
	_, err = part.Write(content)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

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

// TestFileSecurity_ForwardsIntactBody verifies the upstream handler receives the
// full, intact upload after a clean scan (regression test for the body-drain bug).
func TestFileSecurity_ForwardsIntactBody(t *testing.T) {
	pngContent := append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, []byte("payload-bytes-here")...)
	mw := FileSecurity(FileSecurityConfig{AllowedMimeTypes: []string{"image/png"}})

	var receivedLen int
	var receivedContent []byte
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseMultipartForm(1<<20))
		f, _, err := r.FormFile("file")
		require.NoError(t, err)
		defer f.Close()
		b, err := io.ReadAll(f)
		require.NoError(t, err)
		receivedContent = b
		receivedLen = len(b)
		w.WriteHeader(http.StatusOK)
	}))

	req := uploadRequest(t, "file", "test.png", pngContent)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, len(pngContent), receivedLen)
	assert.Equal(t, pngContent, receivedContent)
}

func TestFileSecurity_FileTooLarge(t *testing.T) {
	content := append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, make([]byte, 1024)...)
	mw := FileSecurity(FileSecurityConfig{MaxFileSize: 64})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := uploadRequest(t, "file", "big.png", content)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func TestFileSecurity_BodyTooLarge(t *testing.T) {
	content := make([]byte, 4096)
	mw := FileSecurity(FileSecurityConfig{MaxScanBytes: 256})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := uploadRequest(t, "file", "big.bin", content)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

// TestFileSecurity_ScannerUnavailable exercises the fail-open vs fail-closed policy
// when clamd cannot be reached.
func TestFileSecurity_ScannerUnavailable(t *testing.T) {
	pngContent := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}

	tests := []struct {
		name       string
		failOpen   bool
		wantStatus int
	}{
		{"FailClosed", false, http.StatusServiceUnavailable},
		{"FailOpen", true, http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mw := FileSecurity(FileSecurityConfig{
				EnableClamAV: true,
				ClamAVAddr:   "tcp://127.0.0.1:1", // unreachable
				ScanTimeout:  2 * time.Second,
				FailOpen:     tc.failOpen,
			})
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := uploadRequest(t, "file", "test.png", pngContent)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code)
		})
	}
}

// TestFileSecurity_SignatureScan verifies the YARA-lite signature engine blocks
// malicious uploads (>= block severity) while allowing benign content.
func TestFileSecurity_SignatureScan(t *testing.T) {
	const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

	tests := []struct {
		name       string
		fileName   string
		content    []byte
		wantStatus int
		wantBody   string
	}{
		{"clean upload", "notes.txt", []byte("a perfectly benign text file"), http.StatusOK, ""},
		{"eicar blocked", "x.txt", []byte(eicar), http.StatusForbidden, "Malicious content detected"},
		{"php webshell blocked", "shell.txt", []byte(`<?php eval($_POST["c"]); ?>`), http.StatusForbidden, "Malicious content detected"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mw := FileSecurity(FileSecurityConfig{EnableSignatureScan: true})
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := uploadRequest(t, "file", tc.fileName, tc.content)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code)
			if tc.wantBody != "" {
				assert.Contains(t, rec.Body.String(), tc.wantBody)
			}
		})
	}
}

// TestFileSecurity_SignatureScanDisabled confirms signature scanning is opt-in:
// a webshell passes when EnableSignatureScan is false.
func TestFileSecurity_SignatureScanDisabled(t *testing.T) {
	mw := FileSecurity(FileSecurityConfig{EnableSignatureScan: false})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := uploadRequest(t, "file", "shell.txt", []byte(`<?php eval($_POST["c"]); ?>`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestFileSecurity_NonMultipartPassesThrough(t *testing.T) {
	mw := FileSecurity(FileSecurityConfig{})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("plain body")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code)
}
