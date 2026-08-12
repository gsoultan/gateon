// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Root cause: the diagnostics handlers decoded protobuf request messages with
// encoding/json, which matches incoming keys against the generated
// `json:"anomaly_type"` tag, so the dashboard's protojson spelling
// "anomalyType" matched nothing and AnomalyType silently stayed empty.
//
// The consequence was not a 400 but a wrong answer: ApplyRecommendation
// switched on "" and returned "Automatic resolution for '' is not implemented
// yet" for every anomaly, so "Apply automatic fix" never did anything.
//
// Against the pre-fix code the first subtest fails: AnomalyType comes back "".

// The exact body ui/src/hooks/api.ts sends.
const dashboardApplyBody = `{"anomalyType":"unlisted_route","source":"203.0.113.11","threatId":"t-1"}`

func TestDecodeProtoRequestAcceptsDashboardSpelling(t *testing.T) {
	var req gateonv1.ApplyRecommendationRequest

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/diagnostics/recommendation",
		strings.NewReader(dashboardApplyBody))

	if !DecodeProtoRequest(w, r, &req) {
		t.Fatalf("decode refused the dashboard's own request body: %d %s", w.Code, w.Body)
	}
	if req.GetAnomalyType() != "unlisted_route" {
		t.Errorf("AnomalyType = %q, want %q; ApplyRecommendation switches on this "+
			"field, so an empty value silently selects the not-implemented branch",
			req.GetAnomalyType(), "unlisted_route")
	}
	if req.GetThreatId() != "t-1" {
		t.Errorf("ThreatId = %q, want %q", req.GetThreatId(), "t-1")
	}
	if req.GetSource() != "203.0.113.11" {
		t.Errorf("Source = %q, want %q", req.GetSource(), "203.0.113.11")
	}
}

// protojson accepts the proto spelling too, so any caller written against the
// .proto rather than the generated TypeScript keeps working.
func TestDecodeProtoRequestAcceptsProtoSpelling(t *testing.T) {
	var req gateonv1.ApplyRecommendationRequest

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/diagnostics/recommendation",
		strings.NewReader(`{"anomaly_type":"waf_violation","source":"198.51.100.7"}`))

	if !DecodeProtoRequest(w, r, &req) {
		t.Fatalf("decode refused the proto spelling: %d %s", w.Code, w.Body)
	}
	if req.GetAnomalyType() != "waf_violation" {
		t.Errorf("AnomalyType = %q, want %q", req.GetAnomalyType(), "waf_violation")
	}
}

// This is the defect itself, pinned so it cannot come back by someone reaching
// for encoding/json again on a proto message. It asserts the *broken* result on
// purpose: the underscore in the struct tag is not a case difference, so
// encoding/json's case-insensitive fallback cannot bridge it.
func TestEncodingJSONCannotDecodeDashboardSpelling(t *testing.T) {
	var req gateonv1.ApplyRecommendationRequest

	if err := json.Unmarshal([]byte(dashboardApplyBody), &req); err != nil {
		t.Fatalf("unmarshal errored: %v", err)
	}
	if req.GetAnomalyType() != "" {
		t.Skip("encoding/json now matches json=anomalyType; DecodeProtoRequest may be simplifiable")
	}
	if req.GetSource() != "203.0.113.11" {
		t.Errorf("Source = %q; a tag with no underscore does match, which is why "+
			"this bug hid — the request looked half-decoded, not empty", req.GetSource())
	}
}

// An empty body stays a zero-value request rather than a 400: several handlers
// take no payload and relied on that.
func TestDecodeProtoRequestAllowsEmptyBody(t *testing.T) {
	var req gateonv1.RunDeepScanRequest

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/security/clamav/scan", strings.NewReader("  \n"))

	if !DecodeProtoRequest(w, r, &req) {
		t.Fatalf("empty body rejected: %d %s", w.Code, w.Body)
	}
}

func TestDecodeProtoRequestRejectsMalformedBody(t *testing.T) {
	var req gateonv1.ApplyRecommendationRequest

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/diagnostics/recommendation",
		strings.NewReader(`{"anomalyType":`))

	if DecodeProtoRequest(w, r, &req) {
		t.Fatal("malformed JSON was accepted")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}
