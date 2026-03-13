package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

func TestWriteProtoResponse(t *testing.T) {
	w := httptest.NewRecorder()
	msg := &gateonv1.ListRoutesResponse{TotalCount: 5}
	WriteProtoResponse(w, http.StatusOK, msg)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if w.Body.Len() == 0 {
		t.Error("body empty")
	}
}
