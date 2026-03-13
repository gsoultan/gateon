package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteHTTPError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		message    string
	}{
		{"with message", http.StatusBadRequest, "invalid json"},
		{"empty message uses StatusText", http.StatusNotFound, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			WriteHTTPError(w, tt.statusCode, tt.message)
			if w.Code != tt.statusCode {
				t.Errorf("status = %d, want %d", w.Code, tt.statusCode)
			}
			if tt.message == "" && w.Body.Len() == 0 {
				t.Error("empty message should produce StatusText body")
			}
		})
	}
}

func TestDecodeRequestBody(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"empty body", "", true},
		{"valid json", `{"id":"1","name":"a"}`, false},
		{"invalid json", `{broken`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("POST", "/", bytes.NewBufferString(tt.body))
			var dst struct{ Id, Name string }
			err := DecodeRequestBody(r, &dst)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeRequestBody() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParsePagination(t *testing.T) {
	tests := []struct {
		name           string
		url            string
		wantPage       int32
		wantPageSize   int32
		wantSearch     string
	}{
		{"empty", "/v1/routes", 0, 0, ""},
		{"with params", "/v1/routes?page=2&page_size=50&search=foo", 2, 50, "foo"},
		{"invalid page", "/v1/routes?page=bad", 0, 0, ""},
		{"invalid page_size", "/v1/routes?page_size=bad", 0, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", tt.url, nil)
			page, pageSize, search := ParsePagination(r)
			if page != tt.wantPage || pageSize != tt.wantPageSize || search != tt.wantSearch {
				t.Errorf("ParsePagination() = (%d, %d, %q), want (%d, %d, %q)",
					page, pageSize, search, tt.wantPage, tt.wantPageSize, tt.wantSearch)
			}
		})
	}
}

