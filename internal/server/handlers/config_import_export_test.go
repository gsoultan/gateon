package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

func TestValidateConfigExport(t *testing.T) {
	tests := []struct {
		name     string
		exp      configExport
		wantErrs int
	}{
		{"empty valid", configExport{}, 0},
		{
			"service missing id and targets",
			configExport{
				Services: []*gateonv1.Service{{Name: "svc", WeightedTargets: nil}},
			},
			2, // missing id or name, no targets
		},
		{
			"route missing service_id",
			configExport{
				Routes: []*gateonv1.Route{{Id: "r1", Rule: "Path(`/`)", ServiceId: ""}},
			},
			1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateConfigExport(&tt.exp)
			if len(errs) != tt.wantErrs {
				t.Errorf("validateConfigExport() = %v (len=%d), want %d errs", errs, len(errs), tt.wantErrs)
			}
		})
	}
}

func TestWriteValidateResponse(t *testing.T) {
	w := httptest.NewRecorder()
	writeValidateResponse(w, true, nil, "")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var out map[string]any
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["valid"] != true {
		t.Errorf("valid = %v", out["valid"])
	}

	// With errors
	w2 := httptest.NewRecorder()
	writeValidateResponse(w2, false, []string{"route r1: missing service_id"}, "")
	if w2.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w2.Code)
	}
	var out2 map[string]any
	if err := json.NewDecoder(w2.Body).Decode(&out2); err != nil {
		t.Fatal(err)
	}
	if out2["valid"] != false {
		t.Errorf("valid = %v", out2["valid"])
	}
}

func TestWriteImportResponse(t *testing.T) {
	w := httptest.NewRecorder()
	exp := &configExport{Routes: []*gateonv1.Route{{}}}
	writeImportResponse(w, exp, nil)
	var out map[string]bool
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out["success"] {
		t.Error("success = false, want true")
	}
}
